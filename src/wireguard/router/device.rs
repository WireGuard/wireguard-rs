use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use log::debug;
use spin::{Mutex, RwLock};
use zerocopy::LayoutVerified;

use super::anti_replay::AntiReplay;
use super::pool::Job;

use super::constants::PARALLEL_QUEUE_SIZE;
use super::inbound;
use super::outbound;

use super::messages::{TransportHeader, TYPE_TRANSPORT};
use super::peer::{new_peer, Peer, PeerHandle};
use super::types::{Callbacks, RouterError};
use super::SIZE_MESSAGE_PREFIX;

use super::route::RoutingTable;
use super::runq::RunQueue;

use super::super::{tun, udp, Endpoint, KeyPair};
use super::ParallelQueue;

pub struct DeviceInner<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    // inbound writer (TUN)
    pub inbound: T,

    // outbound writer (Bind)
    pub outbound: RwLock<(bool, Option<B>)>,

    // routing
    pub recv: RwLock<HashMap<u32, Arc<DecryptionState<E, C, T, B>>>>, // receiver id -> decryption state
    pub table: RoutingTable<Peer<E, C, T, B>>,

    // work queues
    pub queue_outbound: ParallelQueue<Job<Peer<E, C, T, B>, outbound::Outbound>>,
    pub queue_inbound: ParallelQueue<Job<Peer<E, C, T, B>, inbound::Inbound<E, C, T, B>>>,

    // run queues
    pub run_inbound: RunQueue<Peer<E, C, T, B>>,
    pub run_outbound: RunQueue<Peer<E, C, T, B>>,
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
        self.state.queue_outbound.close();
        self.state.queue_inbound.close();

        // close run queues
        self.state.run_outbound.close();
        self.state.run_inbound.close();

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
        let (queue_outbound, mut outrx) = ParallelQueue::new(num_workers, PARALLEL_QUEUE_SIZE);
        let (queue_inbound, mut inrx) = ParallelQueue::new(num_workers, PARALLEL_QUEUE_SIZE);
        let device = Device {
            inner: Arc::new(DeviceInner {
                inbound: tun,
                queue_inbound,
                outbound: RwLock::new((true, None)),
                queue_outbound,
                run_inbound: RunQueue::new(),
                run_outbound: RunQueue::new(),
                recv: RwLock::new(HashMap::new()),
                table: RoutingTable::new(),
            }),
        };

        // start worker threads
        let mut threads = Vec::with_capacity(num_workers);

        // inbound/decryption workers
        for _ in 0..num_workers {
            // parallel workers (parallel processing)
            {
                let device = device.clone();
                let rx = inrx.pop().unwrap();
                threads.push(thread::spawn(move || {
                    log::debug!("inbound parallel router worker started");
                    inbound::parallel(device, rx)
                }));
            }

            // sequential workers (in-order processing)
            {
                let device = device.clone();
                threads.push(thread::spawn(move || {
                    log::debug!("inbound sequential router worker started");
                    inbound::sequential(device)
                }));
            }
        }

        // outbound/encryption workers
        for _ in 0..num_workers {
            // parallel workers (parallel processing)
            {
                let device = device.clone();
                let rx = outrx.pop().unwrap();
                threads.push(thread::spawn(move || {
                    log::debug!("outbound parallel router worker started");
                    outbound::parallel(device, rx)
                }));
            }

            // sequential workers (in-order processing)
            {
                let device = device.clone();
                threads.push(thread::spawn(move || {
                    log::debug!("outbound sequential router worker started");
                    outbound::sequential(device)
                }));
            }
        }

        debug_assert_eq!(threads.len(), num_workers * 4);

        // return exported device handle
        DeviceHandle {
            state: device,
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
    pub fn clear_sending_keys(&self) {
        log::debug!("Clear sending keys");
        // TODO: Implement. Consider: The device does not have an explicit list of peers
    }

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
            "send, packet = {}",
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
            self.state.queue_outbound.send(job);
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
        log::trace!("receive, src: {}", src.into_address());

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
            "handle transport message: (receiver = {}, counter = {})",
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
            log::trace!("schedule decryption of transport message");
            self.state.queue_inbound.send(job);
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
