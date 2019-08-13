use arraydeque::{ArrayDeque, Saturating, Wrapping};
use lifeguard::{Pool, Recycled};
use treebitmap::IpLookupTable;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use spin::RwLock;

use super::super::types::KeyPair;
use super::anti_replay::AntiReplay;

use std::u64;

const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 4);
const MAX_STAGED_PACKETS: usize = 128;

pub struct Device<'a> {
    recv: RwLock<HashMap<u32, Arc<Peer<'a>>>>, // map receiver id -> peer
    ipv4: IpLookupTable<Ipv4Addr, Arc<Peer<'a>>>, // ipv4 trie
    ipv6: IpLookupTable<Ipv6Addr, Arc<Peer<'a>>>, // ipv6 trie
    pool: Pool<Vec<u8>>,                       // message buffer pool
}

struct KeyState(KeyPair, AntiReplay);

struct EncryptionState {
    key: [u8; 32],    // encryption key
    id: u64,          // sender id
    nonce: AtomicU64, // next available nonce
    death: Instant,   // can must the key no longer be used:
                      // (birth + reject-after-time - keepalive-timeout - rekey-timeout)
}

struct KeyWheel {
    next: AtomicPtr<Arc<Option<KeyState>>>, // next key state (unconfirmed)
    current: AtomicPtr<Arc<Option<KeyState>>>, // current key state (used for encryption)
    previous: AtomicPtr<Arc<Option<KeyState>>>, // old key state (used for decryption)
}

pub struct Peer<'a> {
    inorder: Mutex<ArrayDeque<[Option<Recycled<'a, Vec<u8>>>; MAX_STAGED_PACKETS], Saturating>>, // inorder queue
    staged_packets: Mutex<ArrayDeque<[Vec<u8>; MAX_STAGED_PACKETS], Wrapping>>, // packets awaiting handshake
    rx_bytes: AtomicU64,                                                        // received bytes
    tx_bytes: AtomicU64,                                                        // transmitted bytes
    keys: KeyWheel,                                                             // key-wheel
    ekey: AtomicPtr<Arc<EncryptionState>>,                                      // encryption state
    endpoint: AtomicPtr<Arc<Option<SocketAddr>>>,
}

impl<'a> Peer<'a> {
    pub fn set_endpoint(&self, endpoint: SocketAddr) {
        self.endpoint
            .store(&mut Arc::new(Some(endpoint)), Ordering::Relaxed)
    }

    pub fn add_keypair(&self, keypair: KeyPair) {
        let confirmed = keypair.confirmed;
        let mut st_new = Arc::new(Some(KeyState(keypair, AntiReplay::new())));
        let st_previous = self.keys.previous.load(Ordering::Relaxed);
        if confirmed {
            // previous <- current
            self.keys.previous.compare_and_swap(
                st_previous,
                self.keys.current.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );

            // current  <- new
            self.keys.next.store(&mut st_new, Ordering::Relaxed)
        } else {
            // previous <- next
            self.keys.previous.compare_and_swap(
                st_previous,
                self.keys.next.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );

            // next <- new
            self.keys.next.store(&mut st_new, Ordering::Relaxed)
        }
    }

    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }

    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }
}

impl<'a> Device<'a> {
    pub fn new() -> Device<'a> {
        Device {
            recv: RwLock::new(HashMap::new()),
            ipv4: IpLookupTable::new(),
            ipv6: IpLookupTable::new(),
            pool: Pool::with_size_and_max(0, MAX_STAGED_PACKETS * 2),
        }
    }

    pub fn subnets(&self, peer: Arc<Peer<'a>>) -> Vec<(IpAddr, u32)> {
        let mut subnets = Vec::new();

        // extract ipv4 entries
        for subnet in self.ipv4.iter() {
            let (ip, masklen, p) = subnet;
            if Arc::ptr_eq(&peer, p) {
                subnets.push((IpAddr::V4(ip), masklen))
            }
        }

        // extract ipv6 entries
        for subnet in self.ipv6.iter() {
            let (ip, masklen, p) = subnet;
            if Arc::ptr_eq(&peer, p) {
                subnets.push((IpAddr::V6(ip), masklen))
            }
        }

        subnets
    }

    /// Adds a new peer to the device
    ///
    /// # Returns
    ///
    /// A atomic ref. counted peer (with liftime matching the device)
    pub fn add(&mut self) -> Arc<Peer<'a>> {
        Arc::new(Peer {
            inorder: Mutex::new(ArrayDeque::new()),
            staged_packets: Mutex::new(ArrayDeque::new()),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            keys: KeyWheel {
                next: AtomicPtr::new(&mut Arc::new(None)),
                current: AtomicPtr::new(&mut Arc::new(None)),
                previous: AtomicPtr::new(&mut Arc::new(None)),
            },
            // long expired encryption key
            ekey: AtomicPtr::new(&mut Arc::new(EncryptionState {
                key: [0u8; 32],
                id: 0,
                nonce: AtomicU64::new(REJECT_AFTER_MESSAGES),
                death: Instant::now() - Duration::from_secs(31536000),
            })),
            endpoint: AtomicPtr::new(&mut Arc::new(None)),
        })
    }

    pub fn get_buffer(&self) -> Recycled<Vec<u8>> {
        self.pool.new()
    }

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
