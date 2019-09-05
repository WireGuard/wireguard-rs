use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Weak};
use std::thread;

use log::debug;

use spin::Mutex;

use arraydeque::{ArrayDeque, Saturating, Wrapping};
use zerocopy::{AsBytes, LayoutVerified};

use treebitmap::address::Address;
use treebitmap::IpLookupTable;

use super::super::constants::*;
use super::super::types::{Bind, KeyPair, Tun};

use super::anti_replay::AntiReplay;
use super::device::DecryptionState;
use super::device::DeviceInner;
use super::device::EncryptionState;
use super::messages::TransportHeader;

use futures::*;

use super::workers::Operation;
use super::workers::{worker_inbound, worker_outbound};
use super::workers::{JobBuffer, JobInbound, JobOutbound, JobParallel};

use super::constants::MAX_STAGED_PACKETS;
use super::types::Callbacks;

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
    pub staged_packets: Mutex<ArrayDeque<[Vec<u8>; MAX_STAGED_PACKETS], Wrapping>>, // packets awaiting handshake
    pub rx_bytes: AtomicU64,                  // received bytes
    pub tx_bytes: AtomicU64,                  // transmitted bytes
    pub keys: Mutex<KeyWheel>,                // key-wheel
    pub ekey: Mutex<Option<EncryptionState>>, // encryption state
    pub endpoint: Mutex<Option<Arc<SocketAddr>>>,
}

pub struct Peer<C: Callbacks, T: Tun, B: Bind> {
    state: Arc<PeerInner<C, T, B>>,
    thread_outbound: Option<thread::JoinHandle<()>>,
    thread_inbound: Option<thread::JoinHandle<()>>,
}

fn treebit_list<A, E, C: Callbacks, T: Tun, B: Bind>(
    peer: &Arc<PeerInner<C, T, B>>,
    table: &spin::RwLock<IpLookupTable<A, Weak<PeerInner<C, T, B>>>>,
    callback: Box<dyn Fn(A, u32) -> E>,
) -> Vec<E>
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

fn treebit_remove<A: Address, C: Callbacks, T: Tun, B: Bind>(
    peer: &Peer<C, T, B>,
    table: &spin::RwLock<IpLookupTable<A, Weak<PeerInner<C, T, B>>>>,
) {
    let mut m = table.write();

    // collect keys for value
    let mut subnets = vec![];
    for subnet in m.iter() {
        let (ip, masklen, p) = subnet;
        if let Some(p) = p.upgrade() {
            if Arc::ptr_eq(&p, &peer.state) {
                subnets.push((ip, masklen))
            }
        }
    }

    // remove all key mappings
    for (ip, masklen) in subnets {
        let r = m.remove(ip, masklen);
        debug_assert!(r.is_some());
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
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
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
    pub fn confirm_key(&self, kp: Weak<KeyPair>) {
        // upgrade key-pair to strong reference

        // check it is the new unconfirmed key

        // rotate key-wheel
    }

    pub fn send_job(&self, mut msg: Vec<u8>) -> Option<JobParallel> {
        debug_assert!(msg.len() >= mem::size_of::<TransportHeader>());

        // parse / cast
        let (header, _) = LayoutVerified::new_from_prefix(&mut msg[..]).unwrap();
        let mut header: LayoutVerified<&mut [u8], TransportHeader> = header;

        // check if has key
        let key = match self.ekey.lock().as_mut() {
            None => {
                // add to staged packets (create no job)
                debug!("execute callback: call_need_key");
                (self.device.call_need_key)(&self.opaque);
                self.staged_packets.lock().push_back(msg);
                return None;
            }
            Some(mut state) => {
                // avoid integer overflow in nonce
                if state.nonce >= REJECT_AFTER_MESSAGES - 1 {
                    return None;
                }
                debug!("encryption state available, nonce = {}", state.nonce);

                // set transport message fields
                header.f_counter.set(state.nonce);
                header.f_receiver.set(state.id);
                state.nonce += 1;
                state.key
            }
        };

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
    pub fn set_endpoint(&self, endpoint: SocketAddr) {
        *self.state.endpoint.lock() = Some(Arc::new(endpoint))
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
            *self.state.ekey.lock() = Some(EncryptionState {
                id: new.send.id,
                key: new.send.key,
                nonce: 0,
                death: new.birth + REJECT_AFTER_TIME,
            });

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

            // map new id to keypair
            debug_assert!(!recv.contains_key(&new.recv.id));

            recv.insert(
                new.recv.id,
                DecryptionState {
                    confirmed: AtomicBool::new(new.initiator),
                    keypair: Arc::downgrade(&new),
                    key: new.recv.key,
                    protector: spin::Mutex::new(AntiReplay::new()),
                    peer: Arc::downgrade(&self.state),
                    death: new.birth + REJECT_AFTER_TIME,
                },
            );
        }

        // return the released id (for handshake state machine)
        release
    }

    pub fn rx_bytes(&self) -> u64 {
        self.state.rx_bytes.load(Ordering::Relaxed)
    }

    pub fn tx_bytes(&self) -> u64 {
        self.state.tx_bytes.load(Ordering::Relaxed)
    }

    pub fn add_subnet(&self, ip: IpAddr, masklen: u32) {
        match ip {
            IpAddr::V4(v4) => {
                self.state
                    .device
                    .ipv4
                    .write()
                    .insert(v4, masklen, Arc::downgrade(&self.state))
            }
            IpAddr::V6(v6) => {
                self.state
                    .device
                    .ipv6
                    .write()
                    .insert(v6, masklen, Arc::downgrade(&self.state))
            }
        };
    }

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

    pub fn remove_subnets(&self) {
        treebit_remove(self, &self.state.device.ipv4);
        treebit_remove(self, &self.state.device.ipv6);
    }

    fn send(&self, msg: Vec<u8>) {}
}
