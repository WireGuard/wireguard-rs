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

use spin::{Mutex, RwLock};
use treebitmap::IpLookupTable;
use zerocopy::LayoutVerified;

use super::super::types::{Bind, KeyPair, Tun};

use super::anti_replay::AntiReplay;
use super::peer;
use super::peer::{Peer, PeerInner};
use super::SIZE_MESSAGE_PREFIX;

use super::constants::*;
use super::ip::*;

use super::messages::{TransportHeader, TYPE_TRANSPORT};
use super::types::{Callback, Callbacks, KeyCallback, Opaque, PhantomCallbacks, RouterError};
use super::workers::{worker_parallel, JobParallel, Operation};

pub struct DeviceInner<C: Callbacks, T: Tun, B: Bind> {
    // IO & timer callbacks
    pub tun: T,
    pub bind: B,
    pub call_recv: C::CallbackRecv,
    pub call_send: C::CallbackSend,
    pub call_need_key: C::CallbackKey,

    // routing
    pub recv: RwLock<HashMap<u32, Arc<DecryptionState<C, T, B>>>>, // receiver id -> decryption state
    pub ipv4: RwLock<IpLookupTable<Ipv4Addr, Arc<PeerInner<C, T, B>>>>, // ipv4 cryptkey routing
    pub ipv6: RwLock<IpLookupTable<Ipv6Addr, Arc<PeerInner<C, T, B>>>>, // ipv6 cryptkey routing
}

pub struct EncryptionState {
    pub key: [u8; 32],  // encryption key
    pub id: u32,        // receiver id
    pub nonce: u64,     // next available nonce
    pub death: Instant, // (birth + reject-after-time - keepalive-timeout - rekey-timeout)
}

pub struct DecryptionState<C: Callbacks, T: Tun, B: Bind> {
    pub keypair: Arc<KeyPair>,
    pub confirmed: AtomicBool,
    pub protector: Mutex<AntiReplay>,
    pub peer: Arc<PeerInner<C, T, B>>,
    pub death: Instant, // time when the key can no longer be used for decryption
}

pub struct Device<C: Callbacks, T: Tun, B: Bind> {
    state: Arc<DeviceInner<C, T, B>>,     // reference to device state
    handles: Vec<thread::JoinHandle<()>>, // join handles for workers
    queue_next: AtomicUsize,              // next round-robin index
    queues: Vec<Mutex<SyncSender<JobParallel>>>, // work queues (1 per thread)
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
            recv: RwLock::new(HashMap::new()),
            ipv4: RwLock::new(IpLookupTable::new()),
            ipv6: RwLock::new(IpLookupTable::new()),
        });

        // start worker threads
        let mut queues = Vec::with_capacity(num_workers);
        let mut threads = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            let (tx, rx) = sync_channel(WORKER_QUEUE_SIZE);
            queues.push(Mutex::new(tx));
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

#[inline(always)]
fn get_route<C: Callbacks, T: Tun, B: Bind>(
    device: &Arc<DeviceInner<C, T, B>>,
    packet: &[u8],
) -> Option<Arc<PeerInner<C, T, B>>> {
    // ensure version access within bounds
    if packet.len() < 1 {
        return None;
    };

    // cast to correct IP header
    match packet[0] >> 4 {
        VERSION_IP4 => {
            // check length and cast to IPv4 header
            let (header, _) = LayoutVerified::new_from_prefix(packet)?;
            let header: LayoutVerified<&[u8], IPv4Header> = header;

            // lookup destination address
            device
                .ipv4
                .read()
                .longest_match(Ipv4Addr::from(header.f_destination))
                .and_then(|(_, _, p)| Some(p.clone()))
        }
        VERSION_IP6 => {
            // check length and cast to IPv6 header
            let (header, packet) = LayoutVerified::new_from_prefix(packet)?;
            let header: LayoutVerified<&[u8], IPv6Header> = header;

            // lookup destination address
            device
                .ipv6
                .read()
                .longest_match(Ipv6Addr::from(header.f_destination))
                .and_then(|(_, _, p)| Some(p.clone()))
        }
        _ => None,
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
    /// - msg: IP packet to crypt-key route
    ///
    pub fn send(&self, msg: Vec<u8>) -> Result<(), RouterError> {
        // ignore header prefix (for in-place transport message construction)
        let packet = &msg[SIZE_MESSAGE_PREFIX..];

        // lookup peer based on IP packet destination address
        let peer = get_route(&self.state, packet).ok_or(RouterError::NoCryptKeyRoute)?;

        // schedule for encryption and transmission to peer
        if let Some(job) = peer.send_job(msg) {
            debug_assert_eq!(job.1.op, Operation::Encryption);

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
    /// - src: Source address of the packet
    /// - msg: Encrypted transport message
    ///
    /// # Returns
    ///
    ///
    pub fn recv(&self, src: B::Endpoint, msg: Vec<u8>) -> Result<(), RouterError> {
        // parse / cast
        let (header, _) = match LayoutVerified::new_from_prefix(&msg[..]) {
            Some(v) => v,
            None => {
                return Err(RouterError::MalformedTransportMessage);
            }
        };
        let header: LayoutVerified<&[u8], TransportHeader> = header;
        debug_assert!(
            header.f_type.get() == TYPE_TRANSPORT as u32,
            "this should be checked by the message type multiplexer"
        );

        // lookup peer based on receiver id
        let dec = self.state.recv.read();
        let dec = dec
            .get(&header.f_receiver.get())
            .ok_or(RouterError::UnkownReceiverId)?;

        // schedule for decryption and TUN write
        if let Some(job) = dec.peer.recv_job(src, dec.clone(), msg) {
            debug_assert_eq!(job.1.op, Operation::Decryption);

            // add job to worker queue
            let idx = self.queue_next.fetch_add(1, Ordering::SeqCst);
            self.queues[idx % self.queues.len()]
                .lock()
                .send(job)
                .unwrap();
        }

        Ok(())
    }
}
