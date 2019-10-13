use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::Arc;
use std::thread;

use arraydeque::{ArrayDeque, Wrapping};
use log::debug;
use spin::Mutex;
use treebitmap::address::Address;
use treebitmap::IpLookupTable;
use zerocopy::LayoutVerified;

use super::super::constants::*;
use super::super::types::{bind, tun, Endpoint, KeyPair};

use super::anti_replay::AntiReplay;
use super::device::DecryptionState;
use super::device::DeviceInner;
use super::device::EncryptionState;
use super::messages::TransportHeader;

use futures::*;

use super::workers::Operation;
use super::workers::{worker_inbound, worker_outbound};
use super::workers::{JobBuffer, JobInbound, JobOutbound, JobParallel};
use super::SIZE_MESSAGE_PREFIX;

use super::constants::*;
use super::types::{Callbacks, RouterError};

pub struct KeyWheel {
    next: Option<Arc<KeyPair>>,     // next key state (unconfirmed)
    current: Option<Arc<KeyPair>>,  // current key state (used for encryption)
    previous: Option<Arc<KeyPair>>, // old key state (used for decryption)
    retired: Vec<u32>,              // retired ids
}

pub struct PeerInner<E: Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>> {
    pub device: Arc<DeviceInner<E, C, T, B>>,
    pub opaque: C::Opaque,
    pub outbound: Mutex<SyncSender<JobOutbound>>,
    pub inbound: Mutex<SyncSender<JobInbound<E, C, T, B>>>,
    pub staged_packets: Mutex<ArrayDeque<[Vec<u8>; MAX_STAGED_PACKETS], Wrapping>>,
    pub keys: Mutex<KeyWheel>,
    pub ekey: Mutex<Option<EncryptionState>>,
    pub endpoint: Mutex<Option<E>>,
}

pub struct Peer<E: Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>> {
    state: Arc<PeerInner<E, C, T, B>>,
    thread_outbound: Option<thread::JoinHandle<()>>,
    thread_inbound: Option<thread::JoinHandle<()>>,
}

fn treebit_list<A, R, E: Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>>(
    peer: &Arc<PeerInner<E, C, T, B>>,
    table: &spin::RwLock<IpLookupTable<A, Arc<PeerInner<E, C, T, B>>>>,
    callback: Box<dyn Fn(A, u32) -> R>,
) -> Vec<R>
where
    A: Address,
{
    let mut res = Vec::new();
    for subnet in table.read().iter() {
        let (ip, masklen, p) = subnet;
        if Arc::ptr_eq(&p, &peer) {
            res.push(callback(ip, masklen))
        }
    }
    res
}

fn treebit_remove<E: Endpoint, A: Address, C: Callbacks, T: tun::Writer, B: bind::Writer<E>>(
    peer: &Peer<E, C, T, B>,
    table: &spin::RwLock<IpLookupTable<A, Arc<PeerInner<E, C, T, B>>>>,
) {
    let mut m = table.write();

    // collect keys for value
    let mut subnets = vec![];
    for subnet in m.iter() {
        let (ip, masklen, p) = subnet;
        if Arc::ptr_eq(&p, &peer.state) {
            subnets.push((ip, masklen))
        }
    }

    // remove all key mappings
    for (ip, masklen) in subnets {
        let r = m.remove(ip, masklen);
        debug_assert!(r.is_some());
    }
}

impl EncryptionState {
    fn new(keypair: &Arc<KeyPair>) -> EncryptionState {
        EncryptionState {
            id: keypair.send.id,
            key: keypair.send.key,
            nonce: 0,
            death: keypair.birth + REJECT_AFTER_TIME,
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>> DecryptionState<E, C, T, B> {
    fn new(
        peer: &Arc<PeerInner<E, C, T, B>>,
        keypair: &Arc<KeyPair>,
    ) -> DecryptionState<E, C, T, B> {
        DecryptionState {
            confirmed: AtomicBool::new(keypair.initiator),
            keypair: keypair.clone(),
            protector: spin::Mutex::new(AntiReplay::new()),
            peer: peer.clone(),
            death: keypair.birth + REJECT_AFTER_TIME,
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>> Drop for Peer<E, C, T, B> {
    fn drop(&mut self) {
        let peer = &self.state;

        // remove from cryptkey router

        treebit_remove(self, &peer.device.ipv4);
        treebit_remove(self, &peer.device.ipv6);

        // drop channels

        mem::replace(&mut *peer.inbound.lock(), sync_channel(0).0);
        mem::replace(&mut *peer.outbound.lock(), sync_channel(0).0);

        // join with workers

        mem::replace(&mut self.thread_inbound, None).map(|v| v.join());
        mem::replace(&mut self.thread_outbound, None).map(|v| v.join());

        // release ids from the receiver map

        let mut keys = peer.keys.lock();
        let mut release = Vec::with_capacity(3);

        keys.next.as_ref().map(|k| release.push(k.recv.id));
        keys.current.as_ref().map(|k| release.push(k.recv.id));
        keys.previous.as_ref().map(|k| release.push(k.recv.id));

        if release.len() > 0 {
            let mut recv = peer.device.recv.write();
            for id in &release {
                recv.remove(id);
            }
        }

        // null key-material

        keys.next = None;
        keys.current = None;
        keys.previous = None;

        *peer.ekey.lock() = None;
        *peer.endpoint.lock() = None;

        debug!("peer dropped & removed from device");
    }
}

pub fn new_peer<E: Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>>(
    device: Arc<DeviceInner<E, C, T, B>>,
    opaque: C::Opaque,
) -> Peer<E, C, T, B> {
    let (out_tx, out_rx) = sync_channel(128);
    let (in_tx, in_rx) = sync_channel(128);

    // allocate peer object
    let peer = {
        let device = device.clone();
        Arc::new(PeerInner {
            opaque,
            device,
            inbound: Mutex::new(in_tx),
            outbound: Mutex::new(out_tx),
            ekey: spin::Mutex::new(None),
            endpoint: spin::Mutex::new(None),
            keys: spin::Mutex::new(KeyWheel {
                next: None,
                current: None,
                previous: None,
                retired: vec![],
            }),
            staged_packets: spin::Mutex::new(ArrayDeque::new()),
        })
    };

    // spawn outbound thread
    let thread_inbound = {
        let peer = peer.clone();
        let device = device.clone();
        thread::spawn(move || worker_outbound(device, peer, out_rx))
    };

    // spawn inbound thread
    let thread_outbound = {
        let peer = peer.clone();
        let device = device.clone();
        thread::spawn(move || worker_inbound(device, peer, in_rx))
    };

    Peer {
        state: peer,
        thread_inbound: Some(thread_inbound),
        thread_outbound: Some(thread_outbound),
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>> PeerInner<E, C, T, B> {
    fn send_staged(&self) -> bool {
        debug!("peer.send_staged");
        let mut sent = false;
        let mut staged = self.staged_packets.lock();
        loop {
            match staged.pop_front() {
                Some(msg) => {
                    sent = true;
                    self.send_raw(msg);
                }
                None => break sent,
            }
        }
    }

    // Treat the msg as the payload of a transport message
    // Unlike device.send, peer.send_raw does not buffer messages when a key is not available.
    fn send_raw(&self, msg: Vec<u8>) -> bool {
        debug!("peer.send_raw");
        match self.send_job(msg, false) {
            Some(job) => {
                debug!("send_raw: got obtained send_job");
                let index = self.device.queue_next.fetch_add(1, Ordering::SeqCst);
                let queues = self.device.queues.lock();
                match queues[index % queues.len()].send(job) {
                    Ok(_) => true,
                    Err(_) => false,
                }
            }
            None => false,
        }
    }

    pub fn confirm_key(&self, keypair: &Arc<KeyPair>) {
        debug!("peer.confirm_key");
        {
            // take lock and check keypair = keys.next
            let mut keys = self.keys.lock();
            let next = match keys.next.as_ref() {
                Some(next) => next,
                None => {
                    return;
                }
            };
            if !Arc::ptr_eq(&next, keypair) {
                return;
            }

            // allocate new encryption state
            let ekey = Some(EncryptionState::new(&next));

            // rotate key-wheel
            let mut swap = None;
            mem::swap(&mut keys.next, &mut swap);
            mem::swap(&mut keys.current, &mut swap);
            mem::swap(&mut keys.previous, &mut swap);

            // tell the world outside the router that a key was confirmed
            C::key_confirmed(&self.opaque);

            // set new key for encryption
            *self.ekey.lock() = ekey;
        }

        // start transmission of staged packets
        self.send_staged();
    }

    pub fn recv_job(
        &self,
        src: E,
        dec: Arc<DecryptionState<E, C, T, B>>,
        msg: Vec<u8>,
    ) -> Option<JobParallel> {
        let (tx, rx) = oneshot();
        let key = dec.keypair.recv.key;
        match self.inbound.lock().try_send((dec, src, rx)) {
            Ok(_) => Some((
                tx,
                JobBuffer {
                    msg,
                    key: key,
                    okay: false,
                    op: Operation::Decryption,
                },
            )),
            Err(_) => None,
        }
    }

    pub fn send_job(&self, mut msg: Vec<u8>, stage: bool) -> Option<JobParallel> {
        debug!("peer.send_job");
        debug_assert!(
            msg.len() >= mem::size_of::<TransportHeader>(),
            "received message with size: {:}",
            msg.len()
        );

        // parse / cast
        let (header, _) = LayoutVerified::new_from_prefix(&mut msg[..]).unwrap();
        let mut header: LayoutVerified<&mut [u8], TransportHeader> = header;

        // check if has key
        let key = {
            let mut ekey = self.ekey.lock();
            let key = match ekey.as_mut() {
                None => None,
                Some(mut state) => {
                    // avoid integer overflow in nonce
                    if state.nonce >= REJECT_AFTER_MESSAGES - 1 {
                        *ekey = None;
                        None
                    } else {
                        // there should be no stacked packets lingering around
                        debug!("encryption state available, nonce = {}", state.nonce);

                        // set transport message fields
                        header.f_counter.set(state.nonce);
                        header.f_receiver.set(state.id);
                        state.nonce += 1;
                        Some(state.key)
                    }
                }
            };

            // If not suitable key was found:
            //   1. Stage packet for later transmission
            //   2. Request new key
            if key.is_none() && stage {
                self.staged_packets.lock().push_back(msg);
                C::need_key(&self.opaque);
                return None;
            };

            key
        }?;

        // add job to in-order queue and return sendeer to device for inclusion in worker pool
        let (tx, rx) = oneshot();
        match self.outbound.lock().try_send(rx) {
            Ok(_) => Some((
                tx,
                JobBuffer {
                    msg,
                    key,
                    okay: false,
                    op: Operation::Encryption,
                },
            )),
            Err(_) => None,
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>> Peer<E, C, T, B> {
    /// Set the endpoint of the peer
    ///
    /// # Arguments
    ///
    /// - `endpoint`, socket address converted to bind endpoint
    ///
    /// # Note
    ///
    /// This API still permits support for the "sticky socket" behavior,
    /// as sockets should be "unsticked" when manually updating the endpoint
    pub fn set_endpoint(&self, endpoint: E) {
        debug!("peer.set_endpoint");
        *self.state.endpoint.lock() = Some(endpoint);
    }

    /// Returns the current endpoint of the peer (for configuration)
    ///
    /// # Note
    ///
    /// Does not convey potential "sticky socket" information
    pub fn get_endpoint(&self) -> Option<SocketAddr> {
        debug!("peer.get_endpoint");
        self.state
            .endpoint
            .lock()
            .as_ref()
            .map(|e| e.into_address())
    }

    /// Zero all key-material related to the peer
    pub fn zero_keys(&self) {
        debug!("peer.zero_keys");

        let mut release: Vec<u32> = Vec::with_capacity(3);
        let mut keys = self.state.keys.lock();

        // update key-wheel

        mem::replace(&mut keys.next, None).map(|k| release.push(k.local_id()));
        mem::replace(&mut keys.current, None).map(|k| release.push(k.local_id()));
        mem::replace(&mut keys.previous, None).map(|k| release.push(k.local_id()));
        keys.retired.extend(&release[..]);

        // update inbound "recv" map
        {
            let mut recv = self.state.device.recv.write();
            for id in release {
                recv.remove(&id);
            }
        }

        // clear encryption state
        *self.state.ekey.lock() = None;
    }

    /// Add a new keypair
    ///
    /// # Arguments
    ///
    /// - new: The new confirmed/unconfirmed key pair
    ///
    /// # Returns
    ///
    /// A vector of ids which has been released.
    /// These should be released in the handshake module.
    ///
    /// # Note
    ///
    /// The number of ids to be released can be at most 3,
    /// since the only way to add additional keys to the peer is by using this method
    /// and a peer can have at most 3 keys allocated in the router at any time.
    pub fn add_keypair(&self, new: KeyPair) -> Vec<u32> {
        debug!("peer.add_keypair");

        let initiator = new.initiator;
        let release = {
            let new = Arc::new(new);
            let mut keys = self.state.keys.lock();
            let mut release = mem::replace(&mut keys.retired, vec![]);

            // update key-wheel
            if new.initiator {
                // start using key for encryption
                *self.state.ekey.lock() = Some(EncryptionState::new(&new));

                // move current into previous
                keys.previous = keys.current.as_ref().map(|v| v.clone());
                keys.current = Some(new.clone());
            } else {
                // store the key and await confirmation
                keys.previous = keys.next.as_ref().map(|v| v.clone());
                keys.next = Some(new.clone());
            };

            // update incoming packet id map
            {
                debug!("peer.add_keypair: updating inbound id map");
                let mut recv = self.state.device.recv.write();

                // purge recv map of previous id
                keys.previous.as_ref().map(|k| {
                    recv.remove(&k.local_id());
                    release.push(k.local_id());
                });

                // map new id to decryption state
                debug_assert!(!recv.contains_key(&new.recv.id));
                recv.insert(
                    new.recv.id,
                    Arc::new(DecryptionState::new(&self.state, &new)),
                );
            }
            release
        };

        // schedule confirmation
        if initiator {
            debug_assert!(self.state.ekey.lock().is_some());
            debug!("peer.add_keypair: is initiator, must confirm the key");
            // attempt to confirm using staged packets
            if !self.state.send_staged() {
                // fall back to keepalive packet
                let ok = self.send_keepalive();
                debug!(
                    "peer.add_keypair: keepalive for confirmation, sent = {}",
                    ok
                );
            }
            debug!("peer.add_keypair: key attempted confirmed");
        }

        debug_assert!(
            release.len() <= 3,
            "since the key-wheel contains at most 3 keys"
        );
        release
    }

    pub fn send_keepalive(&self) -> bool {
        debug!("peer.send_keepalive");
        self.state.send_raw(vec![0u8; SIZE_MESSAGE_PREFIX])
    }

    /// Map a subnet to the peer
    ///
    /// # Arguments
    ///
    /// - `ip`, the mask of the subnet
    /// - `masklen`, the length of the mask
    ///
    /// # Note
    ///
    /// The `ip` must not have any bits set right of `masklen`.
    /// e.g. `192.168.1.0/24` is valid, while `192.168.1.128/24` is not.
    ///
    /// If an identical value already exists as part of a prior peer,
    /// the allowed IP entry will be removed from that peer and added to this peer.
    pub fn add_subnet(&self, ip: IpAddr, masklen: u32) {
        debug!("peer.add_subnet");
        match ip {
            IpAddr::V4(v4) => {
                self.state
                    .device
                    .ipv4
                    .write()
                    .insert(v4, masklen, self.state.clone())
            }
            IpAddr::V6(v6) => {
                self.state
                    .device
                    .ipv6
                    .write()
                    .insert(v6, masklen, self.state.clone())
            }
        };
    }

    /// List subnets mapped to the peer
    ///
    /// # Returns
    ///
    /// A vector of subnets, represented by as mask/size
    pub fn list_subnets(&self) -> Vec<(IpAddr, u32)> {
        debug!("peer.list_subnets");
        let mut res = Vec::new();
        res.append(&mut treebit_list(
            &self.state,
            &self.state.device.ipv4,
            Box::new(|ip, masklen| (IpAddr::V4(ip), masklen)),
        ));
        res.append(&mut treebit_list(
            &self.state,
            &self.state.device.ipv6,
            Box::new(|ip, masklen| (IpAddr::V6(ip), masklen)),
        ));
        res
    }

    /// Clear subnets mapped to the peer.
    /// After the call, no subnets will be cryptkey routed to the peer.
    /// Used for the UAPI command "replace_allowed_ips=true"
    pub fn remove_subnets(&self) {
        debug!("peer.remove_subnets");
        treebit_remove(self, &self.state.device.ipv4);
        treebit_remove(self, &self.state.device.ipv6);
    }

    /// Send a raw message to the peer (used for handshake messages)
    ///
    /// # Arguments
    ///
    /// - `msg`, message body to send to peer
    ///
    /// # Returns
    ///
    /// Unit if packet was sent, or an error indicating why sending failed
    pub fn send(&self, msg: &[u8]) -> Result<(), RouterError> {
        debug!("peer.send");
        let inner = &self.state;
        match inner.endpoint.lock().as_ref() {
            Some(endpoint) => inner
                .device
                .outbound
                .read()
                .as_ref()
                .ok_or(RouterError::SendError)
                .and_then(|w| w.write(msg, endpoint).map_err(|_| RouterError::SendError)),
            None => Err(RouterError::NoEndpoint),
        }
    }

    pub fn purge_staged_packets(&self) {
        self.state.staged_packets.lock().clear();
    }
}
