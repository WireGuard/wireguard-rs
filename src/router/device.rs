use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::Instant;

use crossbeam_deque::{Injector, Worker};
use spin;
use treebitmap::IpLookupTable;

use super::super::types::{Bind, KeyPair, Tun};

use super::anti_replay::AntiReplay;
use super::peer;
use super::peer::{Peer, PeerInner};

use super::types::{Callback, Callbacks, CallbacksPhantom, KeyCallback, Opaque};
use super::workers::{worker_parallel, JobParallel};

pub struct DeviceInner<C: Callbacks, T: Tun> {
    // IO & timer generics
    pub tun: T,
    pub call_recv: C::CallbackRecv,
    pub call_send: C::CallbackSend,
    pub call_need_key: C::CallbackKey,

    // threading and workers
    pub running: AtomicBool,             // workers running?
    pub parked: AtomicBool,              // any workers parked?
    pub injector: Injector<JobParallel>, // parallel enc/dec task injector

    // routing
    pub recv: spin::RwLock<HashMap<u32, DecryptionState<C, T>>>, // receiver id -> decryption state
    pub ipv4: spin::RwLock<IpLookupTable<Ipv4Addr, Weak<PeerInner<C, T>>>>, // ipv4 cryptkey routing
    pub ipv6: spin::RwLock<IpLookupTable<Ipv6Addr, Weak<PeerInner<C, T>>>>, // ipv6 cryptkey routing
}

pub struct EncryptionState {
    pub key: [u8; 32], // encryption key
    pub id: u32,       // sender id
    pub nonce: u64,    // next available nonce
    pub death: Instant, // time when the key no longer can be used for encryption
                       // (birth + reject-after-time - keepalive-timeout - rekey-timeout)
}

pub struct DecryptionState<C: Callbacks, T: Tun> {
    pub key: [u8; 32],
    pub keypair: Weak<KeyPair>,
    pub confirmed: AtomicBool,
    pub protector: spin::Mutex<AntiReplay>,
    pub peer: Weak<PeerInner<C, T>>,
    pub death: Instant, // time when the key can no longer be used for decryption
}

pub struct Device<C: Callbacks, T: Tun>(Arc<DeviceInner<C, T>>, Vec<thread::JoinHandle<()>>);

impl<C: Callbacks, T: Tun> Drop for Device<C, T> {
    fn drop(&mut self) {
        // mark device as stopped
        let device = &self.0;
        device.running.store(false, Ordering::SeqCst);

        // join all worker threads
        while match self.1.pop() {
            Some(handle) => {
                handle.thread().unpark();
                handle.join().unwrap();
                true
            }
            _ => false,
        } {}
    }
}

impl<O: Opaque, R: Callback<O>, S: Callback<O>, K: KeyCallback<O>, T: Tun>
    Device<CallbacksPhantom<O, R, S, K>, T>
{
    pub fn new(
        num_workers: usize,
        tun: T,
        call_recv: R,
        call_send: S,
        call_need_key: K,
    ) -> Device<CallbacksPhantom<O, R, S, K>, T> {
        // allocate shared device state
        let inner = Arc::new(DeviceInner {
            tun,
            call_recv,
            call_send,
            call_need_key,
            parked: AtomicBool::new(false),
            running: AtomicBool::new(true),
            injector: Injector::new(),
            recv: spin::RwLock::new(HashMap::new()),
            ipv4: spin::RwLock::new(IpLookupTable::new()),
            ipv6: spin::RwLock::new(IpLookupTable::new()),
        });

        // allocate work pool resources
        let mut workers = Vec::with_capacity(num_workers);
        let mut stealers = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            let w = Worker::new_fifo();
            stealers.push(w.stealer());
            workers.push(w);
        }

        // start worker threads
        let mut threads = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            let device = inner.clone();
            let stealers = stealers.clone();
            let worker = workers.pop().unwrap();
            threads.push(thread::spawn(move || {
                worker_parallel(device, worker, stealers)
            }));
        }

        // return exported device handle
        Device(inner, threads)
    }
}

impl<C: Callbacks, T: Tun> Device<C, T> {
    /// Adds a new peer to the device
    ///
    /// # Returns
    ///
    /// A atomic ref. counted peer (with liftime matching the device)
    pub fn new_peer(&self, opaque: C::Opaque) -> Peer<C, T> {
        peer::new_peer(self.0.clone(), opaque)
    }

    /// Cryptkey routes and sends a plaintext message (IP packet)
    ///
    /// # Arguments
    ///
    /// - pt_msg: IP packet to cryptkey route
    ///
    pub fn send(&self, pt_msg: &mut [u8]) {
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
}
