use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Weak};
use std::thread;

use spin;

use arraydeque::{ArrayDeque, Wrapping};

use treebitmap::address::Address;
use treebitmap::IpLookupTable;

use super::super::constants::*;
use super::super::types::KeyPair;

use super::anti_replay::AntiReplay;
use super::device::DecryptionState;
use super::device::DeviceInner;
use super::device::EncryptionState;
use super::workers::{worker_inbound, worker_outbound, JobInbound, JobOutbound};

use super::types::{Callback, KeyCallback, Opaque};

const MAX_STAGED_PACKETS: usize = 128;

pub struct KeyWheel {
    next: Option<Arc<KeyPair>>,     // next key state (unconfirmed)
    current: Option<Arc<KeyPair>>,  // current key state (used for encryption)
    previous: Option<Arc<KeyPair>>, // old key state (used for decryption)
    retired: Option<u32>,           // retired id (previous id, after confirming key-pair)
}

pub struct PeerInner<T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>> {
    pub stopped: AtomicBool,
    pub opaque: T,
    pub device: Arc<DeviceInner<T, S, R, K>>,
    pub thread_outbound: spin::Mutex<Option<thread::JoinHandle<()>>>,
    pub thread_inbound: spin::Mutex<Option<thread::JoinHandle<()>>>,
    pub queue_outbound: SyncSender<JobOutbound>,
    pub queue_inbound: SyncSender<JobInbound<T, S, R, K>>,
    pub staged_packets: spin::Mutex<ArrayDeque<[Vec<u8>; MAX_STAGED_PACKETS], Wrapping>>, // packets awaiting handshake
    pub rx_bytes: AtomicU64,                        // received bytes
    pub tx_bytes: AtomicU64,                        // transmitted bytes
    pub keys: spin::Mutex<KeyWheel>,                // key-wheel
    pub ekey: spin::Mutex<Option<EncryptionState>>, // encryption state
    pub endpoint: spin::Mutex<Option<Arc<SocketAddr>>>,
}

pub struct Peer<T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>>(
    Arc<PeerInner<T, S, R, K>>,
);

fn treebit_list<A, O, T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>>(
    peer: &Arc<PeerInner<T, S, R, K>>,
    table: &spin::RwLock<IpLookupTable<A, Weak<PeerInner<T, S, R, K>>>>,
    callback: Box<dyn Fn(A, u32) -> O>,
) -> Vec<O>
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

fn treebit_remove<A: Address, T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>>(
    peer: &Peer<T, S, R, K>,
    table: &spin::RwLock<IpLookupTable<A, Weak<PeerInner<T, S, R, K>>>>,
) {
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

impl<T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>> Drop for Peer<T, S, R, K> {
    fn drop(&mut self) {
        // mark peer as stopped

        let peer = &self.0;
        peer.stopped.store(true, Ordering::SeqCst);

        // remove from cryptkey router

        treebit_remove(self, &peer.device.ipv4);
        treebit_remove(self, &peer.device.ipv6);

        // unpark threads

        peer.thread_inbound
            .lock()
            .as_ref()
            .unwrap()
            .thread()
            .unpark();

        peer.thread_outbound
            .lock()
            .as_ref()
            .unwrap()
            .thread()
            .unpark();

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

pub fn new_peer<T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>>(
    device: Arc<DeviceInner<T, S, R, K>>,
    opaque: T,
) -> Peer<T, S, R, K> {
    // allocate in-order queues
    let (send_inbound, recv_inbound) = sync_channel(MAX_STAGED_PACKETS);
    let (send_outbound, recv_outbound) = sync_channel(MAX_STAGED_PACKETS);

    // allocate peer object
    let peer = {
        let device = device.clone();
        Arc::new(PeerInner {
            opaque,
            stopped: AtomicBool::new(false),
            device: device,
            ekey: spin::Mutex::new(None),
            endpoint: spin::Mutex::new(None),
            queue_inbound: send_inbound,
            queue_outbound: send_outbound,
            keys: spin::Mutex::new(KeyWheel {
                next: None,
                current: None,
                previous: None,
                retired: None,
            }),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            staged_packets: spin::Mutex::new(ArrayDeque::new()),
            thread_inbound: spin::Mutex::new(None),
            thread_outbound: spin::Mutex::new(None),
        })
    };

    // spawn inbound thread
    *peer.thread_inbound.lock() = {
        let peer = peer.clone();
        let device = device.clone();
        Some(thread::spawn(move || {
            worker_outbound(device, peer, recv_outbound)
        }))
    };

    // spawn outbound thread
    *peer.thread_outbound.lock() = {
        let peer = peer.clone();
        let device = device.clone();
        Some(thread::spawn(move || {
            worker_inbound(device, peer, recv_inbound)
        }))
    };

    Peer(peer)
}

impl<T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>> Peer<T, S, R, K> {
    fn new(inner: PeerInner<T, S, R, K>) -> Peer<T, S, R, K> {
        Peer(Arc::new(inner))
    }

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
        let new = Arc::new(new);

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
            keys.current = Some(new.clone());
        } else {
            // store the key and await confirmation
            keys.previous = keys.next.as_ref().map(|v| v.clone());;
            keys.next = Some(new.clone());
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
                    confirmed: AtomicBool::new(new.confirmed),
                    keypair: Arc::downgrade(&new),
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

    pub fn send(&self, msg: Vec<u8>) {}
}
