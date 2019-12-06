use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use arraydeque::{ArrayDeque, Wrapping};
use log::debug;
use spin::Mutex;

use super::super::constants::*;
use super::super::{tun, udp, Endpoint, KeyPair};

use super::anti_replay::AntiReplay;
use super::device::DecryptionState;
use super::device::Device;
use super::device::EncryptionState;
use super::messages::TransportHeader;

use super::constants::*;
use super::types::{Callbacks, RouterError};
use super::SIZE_MESSAGE_PREFIX;

// worker pool related
use super::inbound::Inbound;
use super::outbound::Outbound;
use super::pool::{InorderQueue, Job};

pub struct KeyWheel {
    next: Option<Arc<KeyPair>>,     // next key state (unconfirmed)
    current: Option<Arc<KeyPair>>,  // current key state (used for encryption)
    previous: Option<Arc<KeyPair>>, // old key state (used for decryption)
    retired: Vec<u32>,              // retired ids
}

pub struct PeerInner<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    pub device: Device<E, C, T, B>,
    pub opaque: C::Opaque,
    pub outbound: InorderQueue<Peer<E, C, T, B>, Outbound>,
    pub inbound: InorderQueue<Peer<E, C, T, B>, Inbound<E, C, T, B>>,
    pub staged_packets: Mutex<ArrayDeque<[Vec<u8>; MAX_STAGED_PACKETS], Wrapping>>,
    pub keys: Mutex<KeyWheel>,
    pub ekey: Mutex<Option<EncryptionState>>,
    pub endpoint: Mutex<Option<E>>,
}

pub struct Peer<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    inner: Arc<PeerInner<E, C, T, B>>,
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Clone for Peer<E, C, T, B> {
    fn clone(&self) -> Self {
        Peer {
            inner: self.inner.clone(),
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> PartialEq for Peer<E, C, T, B> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Eq for Peer<E, C, T, B> {}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Deref for Peer<E, C, T, B> {
    type Target = PeerInner<E, C, T, B>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct PeerHandle<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    peer: Peer<E, C, T, B>,
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Deref
    for PeerHandle<E, C, T, B>
{
    type Target = PeerInner<E, C, T, B>;
    fn deref(&self) -> &Self::Target {
        &self.peer
    }
}

impl EncryptionState {
    fn new(keypair: &Arc<KeyPair>) -> EncryptionState {
        EncryptionState {
            nonce: 0,
            keypair: keypair.clone(),
            death: keypair.birth + REJECT_AFTER_TIME,
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> DecryptionState<E, C, T, B> {
    fn new(peer: Peer<E, C, T, B>, keypair: &Arc<KeyPair>) -> DecryptionState<E, C, T, B> {
        DecryptionState {
            confirmed: AtomicBool::new(keypair.initiator),
            keypair: keypair.clone(),
            protector: spin::Mutex::new(AntiReplay::new()),
            death: keypair.birth + REJECT_AFTER_TIME,
            peer,
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Drop for PeerHandle<E, C, T, B> {
    fn drop(&mut self) {
        let peer = &self.peer;

        // remove from cryptkey router

        self.peer.device.table.remove(peer);

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

pub fn new_peer<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
    device: Device<E, C, T, B>,
    opaque: C::Opaque,
) -> PeerHandle<E, C, T, B> {
    // allocate peer object
    let peer = {
        let device = device.clone();
        Peer {
            inner: Arc::new(PeerInner {
                opaque,
                device,
                inbound: InorderQueue::new(),
                outbound: InorderQueue::new(),
                ekey: spin::Mutex::new(None),
                endpoint: spin::Mutex::new(None),
                keys: spin::Mutex::new(KeyWheel {
                    next: None,
                    current: None,
                    previous: None,
                    retired: vec![],
                }),
                staged_packets: spin::Mutex::new(ArrayDeque::new()),
            }),
        }
    };

    PeerHandle { peer }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> PeerInner<E, C, T, B> {
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

        // send to endpoint (if known)
        match self.endpoint.lock().as_ref() {
            Some(endpoint) => {
                let outbound = self.device.outbound.read();
                if outbound.0 {
                    outbound
                        .1
                        .as_ref()
                        .ok_or(RouterError::SendError)
                        .and_then(|w| w.write(msg, endpoint).map_err(|_| RouterError::SendError))
                } else {
                    Ok(())
                }
            }
            None => Err(RouterError::NoEndpoint),
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Peer<E, C, T, B> {
    // Transmit all staged packets
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
        log::debug!("peer.send_raw");
        match self.send_job(msg, false) {
            Some(job) => {
                self.device.outbound_queue.send(job);
                debug!("send_raw: got obtained send_job");
                true
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
    ) -> Option<Job<Self, Inbound<E, C, T, B>>> {
        let job = Job::new(self.clone(), Inbound::new(msg, dec, src));
        self.inbound.send(job.clone());
        Some(job)
    }

    pub fn send_job(&self, msg: Vec<u8>, stage: bool) -> Option<Job<Self, Outbound>> {
        debug!("peer.send_job");
        debug_assert!(
            msg.len() >= mem::size_of::<TransportHeader>(),
            "received message with size: {:}",
            msg.len()
        );

        // check if has key
        let (keypair, counter) = {
            let keypair = {
                // TODO: consider using atomic ptr for ekey state
                let mut ekey = self.ekey.lock();
                match ekey.as_mut() {
                    None => None,
                    Some(mut state) => {
                        // avoid integer overflow in nonce
                        if state.nonce >= REJECT_AFTER_MESSAGES - 1 {
                            *ekey = None;
                            None
                        } else {
                            debug!("encryption state available, nonce = {}", state.nonce);
                            let counter = state.nonce;
                            state.nonce += 1;
                            Some((state.keypair.clone(), counter))
                        }
                    }
                }
            };

            // If not suitable key was found:
            //   1. Stage packet for later transmission
            //   2. Request new key
            if keypair.is_none() && stage {
                self.staged_packets.lock().push_back(msg);
                C::need_key(&self.opaque);
                return None;
            };

            keypair
        }?;

        // add job to in-order queue and return sender to device for inclusion in worker pool
        let job = Job::new(self.clone(), Outbound::new(msg, keypair, counter));
        self.outbound.send(job.clone());
        Some(job)
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> PeerHandle<E, C, T, B> {
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
        *self.peer.endpoint.lock() = Some(endpoint);
    }

    /// Returns the current endpoint of the peer (for configuration)
    ///
    /// # Note
    ///
    /// Does not convey potential "sticky socket" information
    pub fn get_endpoint(&self) -> Option<SocketAddr> {
        debug!("peer.get_endpoint");
        self.peer.endpoint.lock().as_ref().map(|e| e.into_address())
    }

    /// Zero all key-material related to the peer
    pub fn zero_keys(&self) {
        debug!("peer.zero_keys");

        let mut release: Vec<u32> = Vec::with_capacity(3);
        let mut keys = self.peer.keys.lock();

        // update key-wheel

        mem::replace(&mut keys.next, None).map(|k| release.push(k.local_id()));
        mem::replace(&mut keys.current, None).map(|k| release.push(k.local_id()));
        mem::replace(&mut keys.previous, None).map(|k| release.push(k.local_id()));
        keys.retired.extend(&release[..]);

        // update inbound "recv" map
        {
            let mut recv = self.peer.device.recv.write();
            for id in release {
                recv.remove(&id);
            }
        }

        // clear encryption state
        *self.peer.ekey.lock() = None;
    }

    pub fn down(&self) {
        self.zero_keys();
    }

    pub fn up(&self) {}

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
        log::trace!("Router, add_keypair: {:?}", new);

        let initiator = new.initiator;
        let release = {
            let new = Arc::new(new);
            let mut keys = self.peer.keys.lock();
            let mut release = mem::replace(&mut keys.retired, vec![]);

            // update key-wheel
            if new.initiator {
                // start using key for encryption
                *self.peer.ekey.lock() = Some(EncryptionState::new(&new));

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
                let mut recv = self.peer.device.recv.write();

                // purge recv map of previous id
                keys.previous.as_ref().map(|k| {
                    recv.remove(&k.local_id());
                    release.push(k.local_id());
                });

                // map new id to decryption state
                debug_assert!(!recv.contains_key(&new.recv.id));
                recv.insert(
                    new.recv.id,
                    Arc::new(DecryptionState::new(self.peer.clone(), &new)),
                );
            }
            release
        };

        // schedule confirmation
        if initiator {
            debug_assert!(self.peer.ekey.lock().is_some());
            debug!("peer.add_keypair: is initiator, must confirm the key");
            // attempt to confirm using staged packets
            if !self.peer.send_staged() {
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
        self.peer.send_raw(vec![0u8; SIZE_MESSAGE_PREFIX])
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
    pub fn add_allowed_ip(&self, ip: IpAddr, masklen: u32) {
        self.peer
            .device
            .table
            .insert(ip, masklen, self.peer.clone())
    }

    /// List subnets mapped to the peer
    ///
    /// # Returns
    ///
    /// A vector of subnets, represented by as mask/size
    pub fn list_allowed_ips(&self) -> Vec<(IpAddr, u32)> {
        self.peer.device.table.list(&self.peer)
    }

    /// Clear subnets mapped to the peer.
    /// After the call, no subnets will be cryptkey routed to the peer.
    /// Used for the UAPI command "replace_allowed_ips=true"
    pub fn remove_allowed_ips(&self) {
        self.peer.device.table.remove(&self.peer)
    }

    pub fn clear_src(&self) {
        (*self.peer.endpoint.lock()).as_mut().map(|e| e.clear_src());
    }

    pub fn purge_staged_packets(&self) {
        self.peer.staged_packets.lock().clear();
    }
}
