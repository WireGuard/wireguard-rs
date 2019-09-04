use std::cmp;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Weak};
use std::thread;
use std::time::Instant;

use log::debug;

use spin;
use treebitmap::IpLookupTable;

use super::super::types::{Bind, KeyPair, Tun};

use super::anti_replay::AntiReplay;
use super::peer;
use super::peer::{Peer, PeerInner};
use super::SIZE_MESSAGE_PREFIX;

use super::constants::WORKER_QUEUE_SIZE;
use super::messages::TYPE_TRANSPORT;
use super::types::{Callback, Callbacks, KeyCallback, Opaque, PhantomCallbacks, RouterError};
use super::workers::{worker_parallel, JobParallel};

// minimum sizes for IP headers
const SIZE_IP4_HEADER: usize = 16;
const SIZE_IP6_HEADER: usize = 36;

const VERSION_IP4: u8 = 4;
const VERSION_IP6: u8 = 6;

const OFFSET_IP4_DST: usize = 16;
const OFFSET_IP6_DST: usize = 24;

pub struct DeviceInner<C: Callbacks, T: Tun, B: Bind> {
    // IO & timer generics
    pub tun: T,
    pub bind: B,
    pub call_recv: C::CallbackRecv,
    pub call_send: C::CallbackSend,
    pub call_need_key: C::CallbackKey,

    // routing
    pub recv: spin::RwLock<HashMap<u32, DecryptionState<C, T, B>>>, // receiver id -> decryption state
    pub ipv4: spin::RwLock<IpLookupTable<Ipv4Addr, Weak<PeerInner<C, T, B>>>>, // ipv4 cryptkey routing
    pub ipv6: spin::RwLock<IpLookupTable<Ipv6Addr, Weak<PeerInner<C, T, B>>>>, // ipv6 cryptkey routing
}

pub struct EncryptionState {
    pub key: [u8; 32],  // encryption key
    pub id: u32,        // receiver id
    pub nonce: u64,     // next available nonce
    pub death: Instant, // (birth + reject-after-time - keepalive-timeout - rekey-timeout)
}

pub struct DecryptionState<C: Callbacks, T: Tun, B: Bind> {
    pub key: [u8; 32],
    pub keypair: Weak<KeyPair>,
    pub confirmed: AtomicBool,
    pub protector: spin::Mutex<AntiReplay>,
    pub peer: Weak<PeerInner<C, T, B>>,
    pub death: Instant, // time when the key can no longer be used for decryption
}

pub struct Device<C: Callbacks, T: Tun, B: Bind> {
    pub state: Arc<DeviceInner<C, T, B>>, // reference to device state
    pub handles: Vec<thread::JoinHandle<()>>, // join handles for workers
    pub queue_next: AtomicUsize,          // next round-robin index
    pub queues: Vec<spin::Mutex<SyncSender<JobParallel>>>, // work queues (1 per thread)
}

impl<C: Callbacks, T: Tun, B: Bind> Drop for Device<C, T, B> {
    fn drop(&mut self) {
        // drop all queues
        while self.queues.pop().is_some() {}

        // join all worker threads
        while match self.handles.pop() {
            Some(handle) => {
                handle.thread().unpark();
                handle.join().unwrap();
                true
            }
            _ => false,
        } {}

        debug!("device dropped");
    }
}

impl<O: Opaque, R: Callback<O>, S: Callback<O>, K: KeyCallback<O>, T: Tun, B: Bind>
    Device<PhantomCallbacks<O, R, S, K>, T, B>
{
    pub fn new(
        num_workers: usize,
        tun: T,
        bind: B,
        call_send: S,
        call_recv: R,
        call_need_key: K,
    ) -> Device<PhantomCallbacks<O, R, S, K>, T, B> {
        // allocate shared device state
        let inner = Arc::new(DeviceInner {
            tun,
            bind,
            call_recv,
            call_send,
            call_need_key,
            recv: spin::RwLock::new(HashMap::new()),
            ipv4: spin::RwLock::new(IpLookupTable::new()),
            ipv6: spin::RwLock::new(IpLookupTable::new()),
        });

        // start worker threads
        let mut queues = Vec::with_capacity(num_workers);
        let mut threads = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            let (tx, rx) = sync_channel(WORKER_QUEUE_SIZE);
            queues.push(spin::Mutex::new(tx));
            threads.push(thread::spawn(move || worker_parallel(rx)));
        }

        // return exported device handle
        Device {
            state: inner,
            handles: threads,
            queue_next: AtomicUsize::new(0),
            queues: queues,
        }
    }
}

impl<C: Callbacks, T: Tun, B: Bind> Device<C, T, B> {
    /// Adds a new peer to the device
    ///
    /// # Returns
    ///
    /// A atomic ref. counted peer (with liftime matching the device)
    pub fn new_peer(&self, opaque: C::Opaque) -> Peer<C, T, B> {
        peer::new_peer(self.state.clone(), opaque)
    }

    /// Cryptkey routes and sends a plaintext message (IP packet)
    ///
    /// # Arguments
    ///
    /// - pt_msg: IP packet to cryptkey route
    ///
    pub fn send(&self, msg: Vec<u8>) -> Result<(), RouterError> {
        // ensure that the type field access is within bounds
        if msg.len() < cmp::min(SIZE_IP4_HEADER, SIZE_IP6_HEADER) + SIZE_MESSAGE_PREFIX {
            return Err(RouterError::MalformedIPHeader);
        }

        // ignore header prefix (for in-place transport message construction)
        let packet = &msg[SIZE_MESSAGE_PREFIX..];

        // lookup peer based on IP packet destination address
        let peer = match packet[0] >> 4 {
            VERSION_IP4 => {
                if msg.len() >= SIZE_IP4_HEADER {
                    // extract IPv4 destination address
                    let mut dst = [0u8; 4];
                    dst.copy_from_slice(&packet[OFFSET_IP4_DST..OFFSET_IP4_DST + 4]);
                    let dst = Ipv4Addr::from(dst);

                    // lookup peer (project unto and clone "value" field)
                    self.state
                        .ipv4
                        .read()
                        .longest_match(dst)
                        .and_then(|(_, _, p)| p.upgrade())
                        .ok_or(RouterError::NoCryptKeyRoute)
                } else {
                    Err(RouterError::MalformedIPHeader)
                }
            }
            VERSION_IP6 => {
                if msg.len() >= SIZE_IP6_HEADER {
                    // extract IPv6 destination address
                    let mut dst = [0u8; 16];
                    dst.copy_from_slice(&packet[OFFSET_IP6_DST..OFFSET_IP6_DST + 16]);
                    let dst = Ipv6Addr::from(dst);

                    // lookup peer (project unto and clone "value" field)
                    self.state
                        .ipv6
                        .read()
                        .longest_match(dst)
                        .and_then(|(_, _, p)| p.upgrade())
                        .ok_or(RouterError::NoCryptKeyRoute)
                } else {
                    Err(RouterError::MalformedIPHeader)
                }
            }
            _ => Err(RouterError::MalformedIPHeader),
        }?;

        // schedule for encryption and transmission to peer
        if let Some(job) = peer.send_job(msg) {
            // add job to worker queue
            let idx = self.queue_next.fetch_add(1, Ordering::SeqCst);
            self.queues[idx % self.queues.len()]
                .lock()
                .send(job)
                .unwrap();
        }

        Ok(())
    }

    /// Receive an encrypted transport message
    ///
    /// # Arguments
    ///
    /// - msg: Encrypted transport message
    pub fn recv(&self, msg: Vec<u8>) -> Result<(), RouterError> {
        // ensure that the type field access is within bounds
        if msg.len() < SIZE_MESSAGE_PREFIX || msg[0] != TYPE_TRANSPORT {
            return Err(RouterError::MalformedTransportMessage);
        }

        // parse / cast

        // lookup peer based on receiver id

        unimplemented!();
    }
}
