use arraydeque::{ArrayDeque, Wrapping};
use treebitmap::IpLookupTable;

use crossbeam_deque::{Injector, Steal};
use std::collections::HashMap;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

use spin;

use super::super::types::KeyPair;
use super::anti_replay::AntiReplay;

use std::u64;

const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 4);
const MAX_STAGED_PACKETS: usize = 128;

struct DeviceInner {
    stopped: AtomicBool,
    injector: Injector<()>, // parallel enc/dec task injector
    threads: Vec<thread::JoinHandle<()>>,
    recv: spin::RwLock<HashMap<u32, DecryptionState>>,
    ipv4: IpLookupTable<Ipv4Addr, Weak<PeerInner>>,
    ipv6: IpLookupTable<Ipv6Addr, Weak<PeerInner>>,
}

struct PeerInner {
    stopped: AtomicBool,
    thread_outbound: spin::Mutex<thread::JoinHandle<()>>,
    thread_inbound: spin::Mutex<thread::JoinHandle<()>>,
    inorder_outbound: SyncSender<()>,
    inorder_inbound: SyncSender<()>,
    staged_packets: Mutex<ArrayDeque<[Vec<u8>; MAX_STAGED_PACKETS], Wrapping>>, // packets awaiting handshake
    rx_bytes: AtomicU64,                                                        // received bytes
    tx_bytes: AtomicU64,                                                        // transmitted bytes
    keys: spin::Mutex<KeyWheel>,                                                // key-wheel
    ekey: spin::Mutex<EncryptionState>,                                         // encryption state
    endpoint: spin::Mutex<Option<Arc<SocketAddr>>>,
}

struct EncryptionState {
    key: [u8; 32], // encryption key
    id: u32,       // sender id
    nonce: u64,    // next available nonce
    death: Instant, // time when the key no longer can be used for encryption
                   // (birth + reject-after-time - keepalive-timeout - rekey-timeout)
}

struct DecryptionState {
    key: [u8; 32],
    protector: Arc<spin::Mutex<AntiReplay>>,
    peer: Weak<PeerInner>,
    death: Instant, // time when the key can no longer be used for decryption
}

struct KeyWheel {
    next: Option<KeyPair>,     // next key state (unconfirmed)
    current: Option<KeyPair>,  // current key state (used for encryption)
    previous: Option<KeyPair>, // old key state (used for decryption)
}

pub struct Peer(Arc<PeerInner>);
pub struct Device(DeviceInner);

impl Drop for Peer {
    fn drop(&mut self) {
        // mark peer as stopped
        let inner = &self.0;
        inner.stopped.store(true, Ordering::SeqCst);

        // unpark threads to stop
        inner.thread_inbound.lock().thread().unpark();
        inner.thread_outbound.lock().thread().unpark();
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // mark device as stopped
        let inner = &self.0;
        inner.stopped.store(true, Ordering::SeqCst);

        // eat all parallel jobs
        while inner.injector.steal() != Steal::Empty {}
    }
}

impl Peer {
    pub fn set_endpoint(&self, endpoint: SocketAddr) {
        *self.0.endpoint.lock() = Some(Arc::new(endpoint))
    }

    pub fn keypair_confirm(&self, ks: Arc<KeyPair>) {
        *self.0.ekey.lock() = EncryptionState {
            id: ks.send.id,
            key: ks.send.key,
            nonce: 0,
            death: ks.birth + Duration::from_millis(1337), // todo
        };
    }

    fn keypair_add(&self, new: KeyPair) -> Option<u32> {
        let mut keys = self.0.keys.lock();
        let release = keys.previous.map(|k| k.recv.id);

        // update key-wheel
        if new.confirmed {
            // start using key for encryption
            *self.0.ekey.lock() = EncryptionState {
                id: new.send.id,
                key: new.send.key,
                nonce: 0,
                death: new.birth + Duration::from_millis(1337), // todo
            };

            // move current into previous
            keys.previous = keys.current;
            keys.current = Some(new);
        } else {
            // store the key and await confirmation
            keys.previous = keys.next;
            keys.next = Some(new);
        };

        // return the released id (for handshake state machine)
        release
    }

    pub fn rx_bytes(&self) -> u64 {
        self.0.rx_bytes.load(Ordering::Relaxed)
    }

    pub fn tx_bytes(&self) -> u64 {
        self.0.tx_bytes.load(Ordering::Relaxed)
    }
}

impl Device {
    pub fn new(workers: usize) -> Device {
        Device(DeviceInner {
            threads: vec![],
            stopped: AtomicBool::new(false),
            injector: Injector::new(),
            recv: spin::RwLock::new(HashMap::new()),
            ipv4: IpLookupTable::new(),
            ipv6: IpLookupTable::new(),
        })
    }

    pub fn add_subnet(&mut self, ip: IpAddr, masklen: u32, peer: Peer) {
        match ip {
            IpAddr::V4(v4) => self.0.ipv4.insert(v4, masklen, Arc::downgrade(&peer.0)),
            IpAddr::V6(v6) => self.0.ipv6.insert(v6, masklen, Arc::downgrade(&peer.0)),
        };
    }

    pub fn subnets(&self, peer: Peer) -> Vec<(IpAddr, u32)> {
        let mut subnets = Vec::new();

        // extract ipv4 entries
        for subnet in self.0.ipv4.iter() {
            let (ip, masklen, p) = subnet;
            if let Some(p) = p.upgrade() {
                if Arc::ptr_eq(&p, &peer.0) {
                    subnets.push((IpAddr::V4(ip), masklen))
                }
            }
        }

        // extract ipv6 entries
        for subnet in self.0.ipv6.iter() {
            let (ip, masklen, p) = subnet;
            if let Some(p) = p.upgrade() {
                if Arc::ptr_eq(&p, &peer.0) {
                    subnets.push((IpAddr::V6(ip), masklen))
                }
            }
        }

        subnets
    }

    pub fn keypair_add(&self, peer: Peer, new: KeyPair) -> Option<u32> {
        // update key-wheel of peer
        let release = peer.keypair_add(new);

        // update incoming packet id map
        let mut recv = self.0.recv.write();

        // release id of previous keypair
        if let Some(id) = release {
            debug_assert!(recv.contains_key(&id));
            recv.remove(&id);
        };

        // map new id to keypair
        debug_assert!(!recv.contains_key(&new.recv.id));

        recv.insert(
            new.recv.id,
            DecryptionState {
                key: new.recv.key,
                protector: Arc::new(spin::Mutex::new(AntiReplay::new())),
                peer: Arc::downgrade(&peer.0),
                death: new.birth + Duration::from_millis(2600), // todo
            },
        );

        release
    }

    /// Adds a new peer to the device
    ///
    /// # Returns
    ///
    /// A atomic ref. counted peer (with liftime matching the device)
    pub fn add(&mut self) -> () {}

    /// Cryptkey routes and sends a plaintext message (IP packet)
    ///
    /// # Arguments
    ///
    /// - pt_msg: IP packet to cryptkey route
    ///
    /// # Returns
    ///
    /// A peer reference for the peer if no key-pair is currently valid for the destination.
    /// This indicates that a handshake should be initated (see the handshake module).
    /// If this occurs the packet is copied to an internal buffer
    /// and retransmission can be attempted using send_run_queue
    pub fn send(&self, pt_msg: &mut [u8]) -> Arc<Peer> {
        unimplemented!();
    }

    /// Sends a message directly to the peer.
    /// The router device takes care of discovering/managing the endpoint.
    /// This is used for handshake initiation/response messages
    ///
    /// # Arguments
    ///
    /// - peer: Reference to the destination peer
    /// - msg: Message to transmit
    pub fn send_raw(&self, peer: Arc<Peer>, msg: &mut [u8]) {
        unimplemented!();
    }

    /// Flush the queue of buffered messages awaiting transmission
    ///
    /// # Arguments
    ///
    /// - peer: Reference for the peer to flush
    pub fn flush_queue(&self, peer: Arc<Peer>) {
        unimplemented!();
    }

    /// Attempt to route, encrypt and send all elements buffered in the queue
    ///
    /// # Arguments
    ///
    /// # Returns
    ///
    /// A boolean indicating whether packages where sent.
    /// Note: This is used for implicit confirmation of handshakes.
    pub fn send_run_queue(&self, peer: Arc<Peer>) -> bool {
        unimplemented!();
    }

    /// Receive an encrypted transport message
    ///
    /// # Arguments
    ///
    /// - ct_msg: Encrypted transport message
    pub fn recv(&self, ct_msg: &mut [u8]) {
        unimplemented!();
    }

    /// Returns the current endpoint known for the peer
    ///
    /// # Arguments
    ///
    /// - peer: The peer to retrieve the endpoint for
    pub fn get_endpoint(&self, peer: Arc<Peer>) -> SocketAddr {
        unimplemented!();
    }

    pub fn set_endpoint(&self, peer: Arc<Peer>, endpoint: SocketAddr) {
        unimplemented!();
    }

    pub fn new_keypair(&self, peer: Arc<Peer>, keypair: KeyPair) {
        unimplemented!();
    }
}
