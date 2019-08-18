use arraydeque::{ArrayDeque, Wrapping};
use treebitmap::address::Address;
use treebitmap::IpLookupTable;

use crossbeam_deque::{Injector, Steal};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::Instant;

use spin;

use super::super::constants::*;
use super::super::types::KeyPair;
use super::anti_replay::AntiReplay;

use std::u64;

const MAX_STAGED_PACKETS: usize = 128;

struct DeviceInner {
    stopped: AtomicBool,
    injector: Injector<()>,               // parallel enc/dec task injector
    threads: Vec<thread::JoinHandle<()>>, // join handles of worker threads
    recv: spin::RwLock<HashMap<u32, DecryptionState>>, // receiver id -> decryption state
    ipv4: spin::RwLock<IpLookupTable<Ipv4Addr, Weak<PeerInner>>>, // ipv4 cryptkey routing
    ipv6: spin::RwLock<IpLookupTable<Ipv6Addr, Weak<PeerInner>>>, // ipv6 cryptkey routing
}

struct PeerInner {
    stopped: AtomicBool,
    device: Arc<DeviceInner>,
    thread_outbound: spin::Mutex<thread::JoinHandle<()>>,
    thread_inbound: spin::Mutex<thread::JoinHandle<()>>,
    inorder_outbound: SyncSender<()>,
    inorder_inbound: SyncSender<()>,
    staged_packets: spin::Mutex<ArrayDeque<[Vec<u8>; MAX_STAGED_PACKETS], Wrapping>>, // packets awaiting handshake
    rx_bytes: AtomicU64,                        // received bytes
    tx_bytes: AtomicU64,                        // transmitted bytes
    keys: spin::Mutex<KeyWheel>,                // key-wheel
    ekey: spin::Mutex<Option<EncryptionState>>, // encryption state
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
    // keypair: Weak<KeyPair>,
    protector: spin::Mutex<AntiReplay>,
    peer: Weak<PeerInner>,
    death: Instant, // time when the key can no longer be used for decryption
}

struct KeyWheel {
    next: Option<Arc<KeyPair>>,     // next key state (unconfirmed)
    current: Option<Arc<KeyPair>>,  // current key state (used for encryption)
    previous: Option<Arc<KeyPair>>, // old key state (used for decryption)
    retired: Option<u32>,           // retired id (previous id, after confirming key-pair)
}

pub struct Peer(Arc<PeerInner>);
pub struct Device(Arc<DeviceInner>);

fn treebit_list<A, R>(
    peer: &Arc<PeerInner>,
    table: &spin::RwLock<IpLookupTable<A, Weak<PeerInner>>>,
    callback: Box<dyn Fn(A, u32) -> R>,
) -> Vec<R>
where
    A: Address,
{
    let mut res = Vec::new();
    for subnet in table.read().iter() {
        let (ip, masklen, p) = subnet;
        if let Some(p) = p.upgrade() {
            if Arc::ptr_eq(&p, &peer) {
                res.push(callback(ip, masklen))
            }
        }
    }
    res
}

fn treebit_remove<A>(peer: &Peer, table: &spin::RwLock<IpLookupTable<A, Weak<PeerInner>>>)
where
    A: Address,
{
    let mut m = table.write();

    // collect keys for value
    let mut subnets = vec![];
    for subnet in m.iter() {
        let (ip, masklen, p) = subnet;
        if let Some(p) = p.upgrade() {
            if Arc::ptr_eq(&p, &peer.0) {
                subnets.push((ip, masklen))
            }
        }
    }

    // remove all key mappings
    for subnet in subnets {
        let r = m.remove(subnet.0, subnet.1);
        debug_assert!(r.is_some());
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        // mark peer as stopped

        let peer = &self.0;
        peer.stopped.store(true, Ordering::SeqCst);

        // remove from cryptkey router

        treebit_remove(self, &peer.device.ipv4);
        treebit_remove(self, &peer.device.ipv6);

        // unpark threads

        peer.thread_inbound.lock().thread().unpark();
        peer.thread_outbound.lock().thread().unpark();

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

        // null key-material (TODO: extend)

        keys.next = None;
        keys.current = None;
        keys.previous = None;

        *peer.ekey.lock() = None;
        *peer.endpoint.lock() = None;
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // mark device as stopped
        let device = &self.0;
        device.stopped.store(true, Ordering::SeqCst);

        // eat all parallel jobs
        while device.injector.steal() != Steal::Empty {}

        // unpark all threads
        for handle in &device.threads {
            handle.thread().unpark();
        }
    }
}

impl PeerInner {
    pub fn keypair_confirm(&self, kp: Weak<KeyPair>) {
        let mut keys = self.keys.lock();

        // Attempt to upgrade Weak -> Arc
        // (this should ensure that the key is in the key-wheel,
        //  which holds the only strong reference)
        let kp = match kp.upgrade() {
            Some(kp) => kp,
            None => {
                return;
            }
        };

        debug_assert!(
            keys.retired.is_none(),
            "retired spot is not free for previous"
        );

        debug_assert!(
            if let Some(key) = &keys.next {
                Arc::ptr_eq(&kp, &key)
            } else {
                false
            },
            "if next has been overwritten, before confirmation, the key-pair should have been dropped!"
        );

        // enable use for encryption and set confirmed
        *self.ekey.lock() = Some(EncryptionState {
            id: kp.send.id,
            key: kp.send.key,
            nonce: 0,
            death: kp.birth + REJECT_AFTER_TIME,
        });

        // rotate the key-wheel
        let release = keys.previous.as_ref().map(|k| k.recv.id);
        keys.previous = keys.current.as_ref().map(|v| v.clone());
        keys.current = Some(kp.clone());
        keys.retired = release;
    }
}

/// Public interface and handle to the peer
impl Peer {
    pub fn set_endpoint(&self, endpoint: SocketAddr) {
        *self.0.endpoint.lock() = Some(Arc::new(endpoint))
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
        let mut keys = self.0.keys.lock();
        let mut release = Vec::with_capacity(2);

        // collect ids to be released
        keys.retired.map(|v| release.push(v));
        keys.previous.as_ref().map(|k| release.push(k.recv.id));

        // update key-wheel
        if new.confirmed {
            // start using key for encryption
            *self.0.ekey.lock() = Some(EncryptionState {
                id: new.send.id,
                key: new.send.key,
                nonce: 0,
                death: new.birth + REJECT_AFTER_TIME,
            });

            // move current into previous
            keys.previous = keys.current.as_ref().map(|v| v.clone());;
            keys.current = Some(Arc::new(new));
        } else {
            // store the key and await confirmation
            keys.previous = keys.next.as_ref().map(|v| v.clone());;
            keys.next = Some(Arc::new(new));
        };

        // update incoming packet id map
        {
            let mut recv = self.0.device.recv.write();

            // purge recv map of released ids
            for id in &release {
                recv.remove(&id);
            }

            // map new id to keypair
            debug_assert!(!recv.contains_key(&new.recv.id));

            recv.insert(
                new.recv.id,
                DecryptionState {
                    key: new.recv.key,
                    protector: spin::Mutex::new(AntiReplay::new()),
                    peer: Arc::downgrade(&self.0),
                    death: new.birth + REJECT_AFTER_TIME,
                },
            );
        }

        // return the released id (for handshake state machine)
        release
    }

    pub fn rx_bytes(&self) -> u64 {
        self.0.rx_bytes.load(Ordering::Relaxed)
    }

    pub fn tx_bytes(&self) -> u64 {
        self.0.tx_bytes.load(Ordering::Relaxed)
    }

    pub fn add_subnet(&self, ip: IpAddr, masklen: u32) {
        match ip {
            IpAddr::V4(v4) => {
                self.0
                    .device
                    .ipv4
                    .write()
                    .insert(v4, masklen, Arc::downgrade(&self.0))
            }
            IpAddr::V6(v6) => {
                self.0
                    .device
                    .ipv6
                    .write()
                    .insert(v6, masklen, Arc::downgrade(&self.0))
            }
        };
    }

    pub fn list_subnets(&self) -> Vec<(IpAddr, u32)> {
        let mut res = Vec::new();
        res.append(&mut treebit_list(
            &self.0,
            &self.0.device.ipv4,
            Box::new(|ip, masklen| (IpAddr::V4(ip), masklen)),
        ));
        res.append(&mut treebit_list(
            &self.0,
            &self.0.device.ipv6,
            Box::new(|ip, masklen| (IpAddr::V6(ip), masklen)),
        ));
        res
    }
}

impl Device {
    pub fn new(workers: usize) -> Device {
        Device(Arc::new(DeviceInner {
            threads: vec![],
            stopped: AtomicBool::new(false),
            injector: Injector::new(),
            recv: spin::RwLock::new(HashMap::new()),
            ipv4: spin::RwLock::new(IpLookupTable::new()),
            ipv6: spin::RwLock::new(IpLookupTable::new()),
        }))
    }

    /// Adds a new peer to the device
    ///
    /// # Returns
    ///
    /// A atomic ref. counted peer (with liftime matching the device)
    pub fn new_peer(&self) -> Peer {
        // spawn inbound thread
        let (send_inbound, recv_inbound) = sync_channel(1);
        let handle_inbound = thread::spawn(move || {});

        // spawn outbound thread
        let (send_outbound, recv_inbound) = sync_channel(1);
        let handle_outbound = thread::spawn(move || {});

        // allocate peer object
        Peer(Arc::new(PeerInner {
            stopped: AtomicBool::new(false),
            device: self.0.clone(),
            ekey: spin::Mutex::new(None),
            endpoint: spin::Mutex::new(None),
            inorder_inbound: send_inbound,
            inorder_outbound: send_outbound,
            keys: spin::Mutex::new(KeyWheel {
                next: None,
                current: None,
                previous: None,
                retired: None,
            }),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            staged_packets: spin::Mutex::new(ArrayDeque::new()),
            thread_inbound: spin::Mutex::new(handle_inbound),
            thread_outbound: spin::Mutex::new(handle_outbound),
        }))
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
