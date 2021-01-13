use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

use spin::{Mutex, RwLock};
use zerocopy::LayoutVerified;

use super::anti_replay::AntiReplay;

use super::constants::PARALLEL_QUEUE_SIZE;
use super::messages::{TransportHeader, TYPE_TRANSPORT};
use super::peer::{new_peer, Peer, PeerHandle};
use super::types::{Callbacks, RouterError};
use super::SIZE_MESSAGE_PREFIX;

use super::receive::ReceiveJob;
use super::route::RoutingTable;
use super::worker::{worker, JobUnion};

use super::super::{tun, udp, Endpoint, KeyPair};
use super::ParallelQueue;

pub struct DeviceInner<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    // inbound writer (TUN)
    pub(super) inbound: T,

    // outbound writer (Bind)
    pub(super) outbound: RwLock<(bool, Option<B>)>,

    // routing
    #[allow(clippy::type_complexity)]
    pub(super) recv: RwLock<HashMap<u32, Arc<DecryptionState<E, C, T, B>>>>, /* receiver id -> decryption state */
    pub(super) table: RoutingTable<Peer<E, C, T, B>>,

    // work queue
    pub(super) work: ParallelQueue<JobUnion<E, C, T, B>>,
}

pub struct EncryptionState {
    pub(super) keypair: Arc<KeyPair>, // keypair
    pub(super) nonce: u64,            // next available nonce
}

pub struct DecryptionState<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    pub(super) keypair: Arc<KeyPair>,
    pub(super) confirmed: AtomicBool,
    pub(super) protector: Mutex<AntiReplay>,
    pub(super) peer: Peer<E, C, T, B>,
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
        log::debug!("router: dropping device");

        // close worker queue
        self.state.work.close();

        // join all worker threads
        while let Some(handle) = self.handles.pop() {
            handle.thread().unpark();
            handle.join().unwrap();
        }
        log::debug!("router: joined with all workers from pool");
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> DeviceHandle<E, C, T, B> {
    pub fn new(num_workers: usize, tun: T) -> DeviceHandle<E, C, T, B> {
        let (work, mut consumers) = ParallelQueue::new(num_workers, PARALLEL_QUEUE_SIZE);
        let device = Device {
            inner: Arc::new(DeviceInner {
                work,
                inbound: tun,
                outbound: RwLock::new((true, None)),
                recv: RwLock::new(HashMap::new()),
                table: RoutingTable::new(),
            }),
        };

        // start worker threads
        let mut threads = Vec::with_capacity(num_workers);
        while let Some(rx) = consumers.pop() {
            threads.push(thread::spawn(move || worker(rx)));
        }
        debug_assert!(num_workers > 0, "zero worker threads");
        debug_assert_eq!(
            threads.len(),
            num_workers,
            "workers does not match consumers"
        );

        // return exported device handle
        DeviceHandle {
            state: device,
            handles: threads,
        }
    }

    pub fn send_raw(&self, msg: &[u8], dst: &mut E) -> Result<(), B::Error> {
        let bind = self.state.outbound.read();
        if bind.0 {
            if let Some(bind) = bind.1.as_ref() {
                return bind.write(msg, dst);
            }
        }
        Ok(())
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
        peer.send(msg, true);
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

        // create inbound job
        let job = ReceiveJob::new(msg, dec.clone(), src);

        // 1. add to sequential queue (drop if full)
        // 2. then add to parallel work queue (wait if full)
        if dec.peer.inbound.push(job.clone()) {
            self.state.work.send(JobUnion::Inbound(job));
        }
        Ok(())
    }

    /// Set outbound writer
    pub fn set_outbound_writer(&self, new: B) {
        self.state.outbound.write().1 = Some(new);
    }
}
