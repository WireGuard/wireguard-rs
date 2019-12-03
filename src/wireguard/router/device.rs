use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use log::debug;
use spin::{Mutex, RwLock};
use zerocopy::LayoutVerified;

use super::anti_replay::AntiReplay;
use super::pool::Job;

use super::inbound;
use super::outbound;

use super::messages::{TransportHeader, TYPE_TRANSPORT};
use super::peer::{new_peer, Peer, PeerHandle};
use super::types::{Callbacks, RouterError};
use super::SIZE_MESSAGE_PREFIX;

use super::route::RoutingTable;

use super::super::{tun, udp, Endpoint, KeyPair};

pub struct ParallelQueue<T> {
    next: AtomicUsize,                 // next round-robin index
    queues: Vec<Mutex<SyncSender<T>>>, // work queues (1 per thread)
}

impl<T> ParallelQueue<T> {
    fn new(queues: usize) -> (Vec<Receiver<T>>, Self) {
        let mut rxs = vec![];
        let mut txs = vec![];

        for _ in 0..queues {
            let (tx, rx) = sync_channel(128);
            txs.push(Mutex::new(tx));
            rxs.push(rx);
        }

        (
            rxs,
            ParallelQueue {
                next: AtomicUsize::new(0),
                queues: txs,
            },
        )
    }

    pub fn send(&self, v: T) {
        let len = self.queues.len();
        let idx = self.next.fetch_add(1, Ordering::SeqCst);
        let que = self.queues[idx % len].lock();
        que.send(v).unwrap();
    }

    pub fn close(&self) {
        for i in 0..self.queues.len() {
            let (tx, _) = sync_channel(0);
            let queue = &self.queues[i];
            *queue.lock() = tx;
        }
    }
}

pub struct DeviceInner<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    // inbound writer (TUN)
    pub inbound: T,

    // outbound writer (Bind)
    pub outbound: RwLock<(bool, Option<B>)>,

    // routing
    pub recv: RwLock<HashMap<u32, Arc<DecryptionState<E, C, T, B>>>>, // receiver id -> decryption state
    pub table: RoutingTable<Peer<E, C, T, B>>,

    // work queues
    pub outbound_queue: ParallelQueue<Job<Peer<E, C, T, B>, outbound::Outbound>>,
    pub inbound_queue: ParallelQueue<Job<Peer<E, C, T, B>, inbound::Inbound<E, C, T, B>>>,
}

pub struct EncryptionState {
    pub keypair: Arc<KeyPair>, // keypair
    pub nonce: u64,            // next available nonce
    pub death: Instant,        // (birth + reject-after-time - keepalive-timeout - rekey-timeout)
}

pub struct DecryptionState<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    pub keypair: Arc<KeyPair>,
    pub confirmed: AtomicBool,
    pub protector: Mutex<AntiReplay>,
    pub peer: Peer<E, C, T, B>,
    pub death: Instant, // time when the key can no longer be used for decryption
}

pub struct Device<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    inner: Arc<DeviceInner<E, C, T, B>>,
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Clone for Device<E, C, T, B> {
    fn clone(&self) -> Self {
        Device {
            inner: self.inner.clone(),
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> PartialEq
    for Device<E, C, T, B>
{
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Eq for Device<E, C, T, B> {}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Deref for Device<E, C, T, B> {
    type Target = DeviceInner<E, C, T, B>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct DeviceHandle<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    state: Device<E, C, T, B>,            // reference to device state
    handles: Vec<thread::JoinHandle<()>>, // join handles for workers
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Drop
    for DeviceHandle<E, C, T, B>
{
    fn drop(&mut self) {
        debug!("router: dropping device");

        // close worker queues
        self.state.outbound_queue.close();
        self.state.inbound_queue.close();

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

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> DeviceHandle<E, C, T, B> {
    pub fn new(num_workers: usize, tun: T) -> DeviceHandle<E, C, T, B> {
        // allocate shared device state
        let (mut outrx, outbound_queue) = ParallelQueue::new(num_workers);
        let (mut inrx, inbound_queue) = ParallelQueue::new(num_workers);
        let inner = DeviceInner {
            inbound: tun,
            inbound_queue,
            outbound: RwLock::new((true, None)),
            outbound_queue,
            recv: RwLock::new(HashMap::new()),
            table: RoutingTable::new(),
        };

        // start worker threads
        let mut threads = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            let rx = inrx.pop().unwrap();
            threads.push(thread::spawn(move || inbound::worker(rx)));
        }

        for _ in 0..num_workers {
            let rx = outrx.pop().unwrap();
            threads.push(thread::spawn(move || outbound::worker(rx)));
        }

        // return exported device handle
        DeviceHandle {
            state: Device {
                inner: Arc::new(inner),
            },
            handles: threads,
        }
    }

    /// Brings the router down.
    /// When the router is brought down it:
    /// - Prevents transmission of outbound messages.
    pub fn down(&self) {
        self.state.outbound.write().0 = false;
    }

    /// Brints the router up
    /// When the router is brought up it enables the transmission of outbound messages.
    pub fn up(&self) {
        self.state.outbound.write().0 = true;
    }

    /// A new secret key has been set for the device.
    /// According to WireGuard semantics, this should cause all "sending" keys to be discarded.
    pub fn new_sk(&self) {}

    /// Adds a new peer to the device
    ///
    /// # Returns
    ///
    /// A atomic ref. counted peer (with liftime matching the device)
    pub fn new_peer(&self, opaque: C::Opaque) -> PeerHandle<E, C, T, B> {
        new_peer(self.state.clone(), opaque)
    }

    /// Cryptkey routes and sends a plaintext message (IP packet)
    ///
    /// # Arguments
    ///
    /// - msg: IP packet to crypt-key route
    ///
    pub fn send(&self, msg: Vec<u8>) -> Result<(), RouterError> {
        debug_assert!(msg.len() > SIZE_MESSAGE_PREFIX);
        log::trace!(
            "Router, outbound packet = {}",
            hex::encode(&msg[SIZE_MESSAGE_PREFIX..])
        );

        // ignore header prefix (for in-place transport message construction)
        let packet = &msg[SIZE_MESSAGE_PREFIX..];

        // lookup peer based on IP packet destination address
        let peer = self
            .state
            .table
            .get_route(packet)
            .ok_or(RouterError::NoCryptoKeyRoute)?;

        // schedule for encryption and transmission to peer
        if let Some(job) = peer.send_job(msg, true) {
            self.state.outbound_queue.send(job);
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

        log::trace!(
            "Router, handle transport message: (receiver = {}, counter = {})",
            header.f_receiver,
            header.f_counter
        );

        // lookup peer based on receiver id
        let dec = self.state.recv.read();
        let dec = dec
            .get(&header.f_receiver.get())
            .ok_or(RouterError::UnknownReceiverId)?;

        // schedule for decryption and TUN write
        if let Some(job) = dec.peer.recv_job(src, dec.clone(), msg) {
            self.state.inbound_queue.send(job);
        }

        Ok(())
    }

    /// Set outbound writer
    ///
    ///
    pub fn set_outbound_writer(&self, new: B) {
        self.state.outbound.write().1 = Some(new);
    }
}
