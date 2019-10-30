use std::collections::HashMap;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use log::debug;
use spin::{Mutex, RwLock};
use treebitmap::IpLookupTable;
use zerocopy::LayoutVerified;

use super::anti_replay::AntiReplay;
use super::constants::*;

use super::messages::{TransportHeader, TYPE_TRANSPORT};
use super::peer::{new_peer, Peer, PeerInner};
use super::types::{Callbacks, RouterError};
use super::workers::{worker_parallel, JobParallel};
use super::SIZE_MESSAGE_PREFIX;

use super::route::get_route;

use super::super::{bind, tun, Endpoint, KeyPair};

pub struct DeviceInner<E: Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>> {
    // inbound writer (TUN)
    pub inbound: T,

    // outbound writer (Bind)
    pub outbound: RwLock<Option<B>>,

    // routing
    pub recv: RwLock<HashMap<u32, Arc<DecryptionState<E, C, T, B>>>>, // receiver id -> decryption state
    pub ipv4: RwLock<IpLookupTable<Ipv4Addr, Arc<PeerInner<E, C, T, B>>>>, // ipv4 cryptkey routing
    pub ipv6: RwLock<IpLookupTable<Ipv6Addr, Arc<PeerInner<E, C, T, B>>>>, // ipv6 cryptkey routing

    // work queues
    pub queue_next: AtomicUsize, // next round-robin index
    pub queues: Mutex<Vec<SyncSender<JobParallel>>>, // work queues (1 per thread)
}

pub struct EncryptionState {
    pub keypair: Arc<KeyPair>, // keypair
    pub nonce: u64,            // next available nonce
    pub death: Instant,        // (birth + reject-after-time - keepalive-timeout - rekey-timeout)
}

pub struct DecryptionState<E: Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>> {
    pub keypair: Arc<KeyPair>,
    pub confirmed: AtomicBool,
    pub protector: Mutex<AntiReplay>,
    pub peer: Arc<PeerInner<E, C, T, B>>,
    pub death: Instant, // time when the key can no longer be used for decryption
}

pub struct Device<E: Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>> {
    state: Arc<DeviceInner<E, C, T, B>>,  // reference to device state
    handles: Vec<thread::JoinHandle<()>>, // join handles for workers
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>> Drop for Device<E, C, T, B> {
    fn drop(&mut self) {
        debug!("router: dropping device");

        // drop all queues
        {
            let mut queues = self.state.queues.lock();
            while queues.pop().is_some() {}
        }

        // join all worker threads
        while match self.handles.pop() {
            Some(handle) => {
                handle.thread().unpark();
                handle.join().unwrap();
                true
            }
            _ => false,
        } {}

        debug!("router: device dropped");
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>> Device<E, C, T, B> {
    pub fn new(num_workers: usize, tun: T) -> Device<E, C, T, B> {
        // allocate shared device state
        let inner = DeviceInner {
            inbound: tun,
            outbound: RwLock::new(None),
            queues: Mutex::new(Vec::with_capacity(num_workers)),
            queue_next: AtomicUsize::new(0),
            recv: RwLock::new(HashMap::new()),
            ipv4: RwLock::new(IpLookupTable::new()),
            ipv6: RwLock::new(IpLookupTable::new()),
        };

        // start worker threads
        let mut threads = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            let (tx, rx) = sync_channel(WORKER_QUEUE_SIZE);
            inner.queues.lock().push(tx);
            threads.push(thread::spawn(move || worker_parallel(rx)));
        }

        // return exported device handle
        Device {
            state: Arc::new(inner),
            handles: threads,
        }
    }

    /// A new secret key has been set for the device.
    /// According to WireGuard semantics, this should cause all "sending" keys to be discarded.
    pub fn new_sk(&self) {}

    /// Adds a new peer to the device
    ///
    /// # Returns
    ///
    /// A atomic ref. counted peer (with liftime matching the device)
    pub fn new_peer(&self, opaque: C::Opaque) -> Peer<E, C, T, B> {
        new_peer(self.state.clone(), opaque)
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
        let peer = get_route(&self.state, packet).ok_or(RouterError::NoCryptoKeyRoute)?;

        // schedule for encryption and transmission to peer
        if let Some(job) = peer.send_job(msg, true) {
            // add job to worker queue
            let idx = self.state.queue_next.fetch_add(1, Ordering::SeqCst);
            let queues = self.state.queues.lock();
            queues[idx % queues.len()].send(job).unwrap();
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
    pub fn recv(&self, src: E, msg: Vec<u8>) -> Result<(), RouterError> {
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
            .ok_or(RouterError::UnknownReceiverId)?;

        // schedule for decryption and TUN write
        if let Some(job) = dec.peer.recv_job(src, dec.clone(), msg) {
            // add job to worker queue
            let idx = self.state.queue_next.fetch_add(1, Ordering::SeqCst);
            let queues = self.state.queues.lock();
            queues[idx % queues.len()].send(job).unwrap();
        }

        Ok(())
    }

    /// Set outbound writer
    ///
    ///
    pub fn set_outbound_writer(&self, new: B) {
        *self.state.outbound.write() = Some(new);
    }
}
