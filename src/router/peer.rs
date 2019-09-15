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
use super::super::types::{Bind, Endpoint, KeyPair, Tun};

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
    retired: Option<u32>,           // retired id (previous id, after confirming key-pair)
}

pub struct PeerInner<C: Callbacks, T: Tun, B: Bind> {
    pub device: Arc<DeviceInner<C, T, B>>,
    pub opaque: C::Opaque,
    pub outbound: Mutex<SyncSender<JobOutbound>>,
    pub inbound: Mutex<SyncSender<JobInbound<C, T, B>>>,
    pub staged_packets: Mutex<ArrayDeque<[Vec<u8>; MAX_STAGED_PACKETS], Wrapping>>,
    pub keys: Mutex<KeyWheel>,
    pub ekey: Mutex<Option<EncryptionState>>,
    pub endpoint: Mutex<Option<B::Endpoint>>,
}

pub struct Peer<C: Callbacks, T: Tun, B: Bind> {
    state: Arc<PeerInner<C, T, B>>,
    thread_outbound: Option<thread::JoinHandle<()>>,
    thread_inbound: Option<thread::JoinHandle<()>>,
}

fn treebit_list<A, E, C: Callbacks, T: Tun, B: Bind>(
    peer: &Arc<PeerInner<C, T, B>>,
    table: &spin::RwLock<IpLookupTable<A, Arc<PeerInner<C, T, B>>>>,
    callback: Box<dyn Fn(A, u32) -> E>,
) -> Vec<E>
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

fn treebit_remove<A: Address, C: Callbacks, T: Tun, B: Bind>(
    peer: &Peer<C, T, B>,
    table: &spin::RwLock<IpLookupTable<A, Arc<PeerInner<C, T, B>>>>,
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

impl<C: Callbacks, T: Tun, B: Bind> DecryptionState<C, T, B> {
    fn new(peer: &Arc<PeerInner<C, T, B>>, keypair: &Arc<KeyPair>) -> DecryptionState<C, T, B> {
        DecryptionState {
            confirmed: AtomicBool::new(keypair.initiator),
            keypair: keypair.clone(),
            protector: spin::Mutex::new(AntiReplay::new()),
            peer: peer.clone(),
            death: keypair.birth + REJECT_AFTER_TIME,
        }
    }
}

impl<C: Callbacks, T: Tun, B: Bind> Drop for Peer<C, T, B> {
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

pub fn new_peer<C: Callbacks, T: Tun, B: Bind>(
    device: Arc<DeviceInner<C, T, B>>,
    opaque: C::Opaque,
) -> Peer<C, T, B> {
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
                retired: None,
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

impl<C: Callbacks, T: Tun, B: Bind> PeerInner<C, T, B> {
    fn send_staged(&self) -> bool {
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

    fn send_raw(&self, msg: Vec<u8>) -> bool {
        match self.send_job(msg) {
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

        // set new encryption key
        *self.ekey.lock() = ekey;

        // start transmission of staged packets
        self.send_staged();
    }

    pub fn recv_job(
        &self,
        src: B::Endpoint,
        dec: Arc<DecryptionState<C, T, B>>,
        mut msg: Vec<u8>,
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

    pub fn send_job(&self, mut msg: Vec<u8>) -> Option<JobParallel> {
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
                        debug_assert_eq!(self.staged_packets.lock().len(), 0);
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
            if key.is_none() {
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

impl<C: Callbacks, T: Tun, B: Bind> Peer<C, T, B> {
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
    pub fn set_endpoint(&self, address: SocketAddr) {
        *self.state.endpoint.lock() = Some(B::Endpoint::from_address(address));
    }

    pub fn get_endpoint(&self) -> Option<SocketAddr> {
        self.state
            .endpoint
            .lock()
            .as_ref()
            .map(|e| e.into_address())
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
    pub fn add_keypair(&self, new: KeyPair) -> Vec<u32> {
        let mut keys = self.state.keys.lock();
        let mut release = Vec::with_capacity(2);
        let new = Arc::new(new);

        // collect ids to be released
        keys.retired.map(|v| release.push(v));
        keys.previous.as_ref().map(|k| release.push(k.recv.id));

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
            let mut recv = self.state.device.recv.write();

            // purge recv map of released ids
            for id in &release {
                recv.remove(&id);
            }

            // map new id to decryption state
            debug_assert!(!recv.contains_key(&new.recv.id));
            recv.insert(
                new.recv.id,
                Arc::new(DecryptionState::new(&self.state, &new)),
            );
        }

        // schedule confirmation
        if new.initiator {
            // fall back to keepalive packet
            if !self.state.send_staged() {
                let ok = self.keepalive();
                debug!("keepalive for confirmation, sent = {}", ok);
            }
        }

        // return the released id (for handshake state machine)
        release
    }

    pub fn keepalive(&self) -> bool {
        debug!("send keepalive");
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
        let inner = &self.state;
        match inner.endpoint.lock().as_ref() {
            Some(endpoint) => inner
                .device
                .bind
                .send(msg, endpoint)
                .map_err(|_| RouterError::SendError),
            None => Err(RouterError::NoEndpoint),
        }
    }
}
