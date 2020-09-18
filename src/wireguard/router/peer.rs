use super::super::constants::*;
use super::super::{tun, udp, Endpoint, KeyPair};

use super::anti_replay::AntiReplay;
use super::device::DecryptionState;
use super::device::Device;
use super::device::EncryptionState;

use super::constants::*;
use super::types::{Callbacks, RouterError};
use super::SIZE_MESSAGE_PREFIX;

use super::queue::Queue;
use super::receive::ReceiveJob;
use super::send::SendJob;
use super::worker::JobUnion;

use core::mem;
use core::ops::Deref;
use core::sync::atomic::AtomicBool;

use alloc::sync::Arc;

// TODO: consider no_std alternatives
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use arraydeque::{ArrayDeque, Wrapping};
use spin::Mutex;

pub struct KeyWheel {
    next: Option<Arc<KeyPair>>,     // next key state (unconfirmed)
    current: Option<Arc<KeyPair>>,  // current key state (used for encryption)
    previous: Option<Arc<KeyPair>>, // old key state (used for decryption)
    retired: Vec<u32>,              // retired ids
}

pub struct PeerInner<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    pub(super) device: Device<E, C, T, B>,
    pub(super) opaque: C::Opaque,
    pub(super) outbound: Queue<SendJob<E, C, T, B>>,
    pub(super) inbound: Queue<ReceiveJob<E, C, T, B>>,
    pub(super) staged_packets: Mutex<ArrayDeque<[Vec<u8>; MAX_QUEUED_PACKETS], Wrapping>>,
    pub(super) keys: Mutex<KeyWheel>,
    pub(super) enc_key: Mutex<Option<EncryptionState>>,
    pub(super) endpoint: Mutex<Option<E>>,
}

/// A Peer dereferences to its opaque type:
/// This allows the router code to take ownership of the opaque type
/// used for callback events, while still enabling the rest of the code to access the opaque type
/// (which might expose other functionality in their scope) from a Peer pointer.
///
/// e.g. it can take ownership of the timer state of a peer.
impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Deref for PeerInner<E, C, T, B> {
    type Target = C::Opaque;

    fn deref(&self) -> &Self::Target {
        &self.opaque
    }
}

/// A Peer represents a reference to the router state associated with a peer
pub struct Peer<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    inner: Arc<PeerInner<E, C, T, B>>,
}

/// A PeerHandle is a specially designated reference to the peer
/// which removes the peer from the device when dropped.
///
/// A PeerHandle cannot be cloned (unlike the wrapped type).
/// A PeerHandle dereferences to a Peer (meaning you can use it like a Peer struct)
pub struct PeerHandle<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    peer: Peer<E, C, T, B>,
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Clone for Peer<E, C, T, B> {
    fn clone(&self) -> Self {
        Peer {
            inner: self.inner.clone(),
        }
    }
}

/* Equality of peers is defined as pointer equality of
 * the atomic reference counted pointer.
 */
impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> PartialEq for Peer<E, C, T, B> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Eq for Peer<E, C, T, B> {}

/* A peer is transparently dereferenced to the inner type
 *
 */

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Deref for Peer<E, C, T, B> {
    type Target = PeerInner<E, C, T, B>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Deref
    for PeerHandle<E, C, T, B>
{
    type Target = PeerInner<E, C, T, B>;
    fn deref(&self) -> &Self::Target {
        &self.peer
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> fmt::Display
    for PeerHandle<E, C, T, B>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerHandle(format: TODO)")
    }
}

impl EncryptionState {
    fn new(keypair: &Arc<KeyPair>) -> EncryptionState {
        EncryptionState {
            nonce: 0,
            keypair: keypair.clone(),
        }
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> DecryptionState<E, C, T, B> {
    fn new(peer: Peer<E, C, T, B>, keypair: &Arc<KeyPair>) -> DecryptionState<E, C, T, B> {
        DecryptionState {
            confirmed: AtomicBool::new(keypair.initiator),
            keypair: keypair.clone(),
            protector: spin::Mutex::new(AntiReplay::new()),
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

        if let Some(k) = keys.next.as_ref() {
            release.push(k.recv.id)
        }
        if let Some(k) = keys.current.as_ref() {
            release.push(k.recv.id)
        }
        if let Some(k) = keys.previous.as_ref() {
            release.push(k.recv.id)
        }

        if !release.is_empty() {
            let mut recv = peer.device.recv.write();
            for id in &release {
                recv.remove(id);
            }
        }

        // null key-material

        keys.next = None;
        keys.current = None;
        keys.previous = None;

        *peer.enc_key.lock() = None;
        *peer.endpoint.lock() = None;

        log::debug!("peer dropped & removed from device");
    }
}

pub fn new_peer<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
    device: Device<E, C, T, B>,
    opaque: C::Opaque,
) -> PeerHandle<E, C, T, B> {
    // allocate peer object
    let peer = {
        Peer {
            inner: Arc::new(PeerInner {
                opaque,
                device,
                inbound: Queue::new(),
                outbound: Queue::new(),
                enc_key: spin::Mutex::new(None),
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
    pub fn send_raw(&self, msg: &[u8]) -> Result<(), RouterError> {
        // send to endpoint (if known)
        match self.endpoint.lock().as_mut() {
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
    /// Encrypt and send a message to the peer
    ///
    /// Arguments:
    ///
    /// - `msg` : A padded vector holding the message (allows in-place construction of the transport header)
    /// - `stage`: Should the message be staged if no key is available
    pub(super) fn send(&self, msg: Vec<u8>, stage: bool) {
        // check if key available
        let (job, need_key) = {
            let mut enc_key = self.enc_key.lock();
            match enc_key.as_mut() {
                None => {
                    log::debug!("no key encryption key available");
                    if stage {
                        self.staged_packets.lock().push_back(msg);
                    };
                    (None, true)
                }
                Some(mut state) => {
                    // avoid integer overflow in nonce
                    if state.nonce >= REJECT_AFTER_MESSAGES - 1 {
                        log::debug!("encryption key expired");
                        *enc_key = None;
                        if stage {
                            self.staged_packets.lock().push_back(msg);
                        }
                        (None, true)
                    } else {
                        log::debug!("encryption state available, nonce = {}", state.nonce);
                        let job =
                            SendJob::new(msg, state.nonce, state.keypair.clone(), self.clone());
                        if self.outbound.push(job.clone()) {
                            state.nonce += 1;
                            (Some(job), false)
                        } else {
                            (None, false)
                        }
                    }
                }
            }
        };

        if need_key {
            log::debug!("request new key");
            debug_assert!(job.is_none());
            C::need_key(&self.opaque);
        };

        if let Some(job) = job {
            log::debug!("schedule outbound job");
            self.device.work.send(JobUnion::Outbound(job))
        }
    }

    // Transmit all staged packets
    fn send_staged(&self) -> bool {
        log::trace!("peer.send_staged");
        let mut sent = false;
        let mut staged = self.staged_packets.lock();
        loop {
            match staged.pop_front() {
                Some(msg) => {
                    sent = true;
                    self.send(msg, false);
                }
                None => break sent,
            }
        }
    }

    pub(super) fn confirm_key(&self, keypair: &Arc<KeyPair>) {
        log::trace!("peer.confirm_key");
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
            *self.enc_key.lock() = ekey;
        }

        // start transmission of staged packets
        self.send_staged();
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
        log::trace!("peer.set_endpoint");
        *self.peer.endpoint.lock() = Some(endpoint);
    }

    pub fn opaque(&self) -> &C::Opaque {
        &self.opaque
    }

    /// Returns the current endpoint of the peer (for configuration)
    ///
    /// # Note
    ///
    /// Does not convey potential "sticky socket" information
    pub fn get_endpoint(&self) -> Option<SocketAddr> {
        log::trace!("peer.get_endpoint");
        self.peer.endpoint.lock().as_ref().map(|e| e.into_address())
    }

    /// Zero all key-material related to the peer
    pub fn zero_keys(&self) {
        log::trace!("peer.zero_keys");

        let mut release: Vec<u32> = Vec::with_capacity(3);
        let mut keys = self.peer.keys.lock();

        // update key-wheel

        if let Some(k) = mem::replace(&mut keys.next, None) {
            release.push(k.local_id())
        }
        if let Some(k) = mem::replace(&mut keys.current, None) {
            release.push(k.local_id())
        }
        if let Some(k) = mem::replace(&mut keys.previous, None) {
            release.push(k.local_id())
        }
        keys.retired.extend(&release[..]);

        // update inbound "recv" map
        {
            let mut recv = self.peer.device.recv.write();
            for id in release {
                recv.remove(&id);
            }
        }

        // clear encryption state
        *self.peer.enc_key.lock() = None;
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
                *self.peer.enc_key.lock() = Some(EncryptionState::new(&new));

                // move current into previous
                keys.previous = keys.current.as_ref().cloned();
                keys.current = Some(new.clone());
            } else {
                // store the key and await confirmation
                keys.previous = keys.next.as_ref().cloned();
                keys.next = Some(new.clone());
            };

            // update incoming packet id map
            {
                log::trace!("peer.add_keypair: updating inbound id map");
                let mut recv = self.peer.device.recv.write();

                // purge recv map of previous id
                if let Some(k) = &keys.previous {
                    recv.remove(&k.local_id());
                    release.push(k.local_id());
                }

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
            debug_assert!(self.peer.enc_key.lock().is_some());
            log::trace!("peer.add_keypair: is initiator, must confirm the key");
            // attempt to confirm using staged packets
            if !self.peer.send_staged() {
                // fall back to keepalive packet
                self.send_keepalive();
                log::debug!("peer.add_keypair: keepalive for confirmation",);
            }
            log::trace!("peer.add_keypair: key attempted confirmed");
        }

        debug_assert!(
            release.len() <= 3,
            "since the key-wheel contains at most 3 keys"
        );
        release
    }

    pub fn send_keepalive(&self) {
        log::trace!("peer.send_keepalive");
        self.peer.send(vec![0u8; SIZE_MESSAGE_PREFIX], false)
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
        if let Some(e) = (*self.peer.endpoint.lock()).as_mut() {
            e.clear_src()
        }
    }

    pub fn purge_staged_packets(&self) {
        self.peer.staged_packets.lock().clear();
    }
}
