use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::Instant;

use crossbeam_deque::{Injector, Steal, Stealer, Worker};
use spin;
use treebitmap::IpLookupTable;

use super::super::types::KeyPair;
use super::anti_replay::AntiReplay;
use super::peer;
use super::peer::{Peer, PeerInner};

use super::types::{Callback, KeyCallback, Opaque};
use super::workers::{worker_parallel, JobParallel};

pub struct DeviceInner<T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>> {
    // threading and workers
    pub running: AtomicBool,             // workers running?
    pub parked: AtomicBool,              // any workers parked?
    pub injector: Injector<JobParallel>, // parallel enc/dec task injector

    // unboxed callbacks (used for timers and handshake requests)
    pub event_send: S,     // called when authenticated message send
    pub event_recv: R,     // called when authenticated message received
    pub event_need_key: K, // called when new key material is required

    // routing
    pub recv: spin::RwLock<HashMap<u32, DecryptionState<T, S, R, K>>>, // receiver id -> decryption state
    pub ipv4: spin::RwLock<IpLookupTable<Ipv4Addr, Weak<PeerInner<T, S, R, K>>>>, // ipv4 cryptkey routing
    pub ipv6: spin::RwLock<IpLookupTable<Ipv6Addr, Weak<PeerInner<T, S, R, K>>>>, // ipv6 cryptkey routing
}

pub struct EncryptionState {
    pub key: [u8; 32], // encryption key
    pub id: u32,       // sender id
    pub nonce: u64,    // next available nonce
    pub death: Instant, // time when the key no longer can be used for encryption
                       // (birth + reject-after-time - keepalive-timeout - rekey-timeout)
}

pub struct DecryptionState<T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>> {
    pub key: [u8; 32],
    pub keypair: Weak<KeyPair>,
    pub confirmed: AtomicBool,
    pub protector: spin::Mutex<AntiReplay>,
    pub peer: Weak<PeerInner<T, S, R, K>>,
    pub death: Instant, // time when the key can no longer be used for decryption
}

pub struct Device<T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>>(
    Arc<DeviceInner<T, S, R, K>>,
    Vec<thread::JoinHandle<()>>,
);

impl<T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>> Drop for Device<T, S, R, K> {
    fn drop(&mut self) {
        // mark device as stopped
        let device = &self.0;
        device.running.store(false, Ordering::SeqCst);

        // eat all parallel jobs
        while match device.injector.steal() {
            Steal::Empty => true,
            _ => false,
        } {}

        // unpark all threads
        for handle in &self.1 {
            handle.thread().unpark();
        }
    }
}

impl<T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>> Device<T, S, R, K> {
    pub fn new(
        num_workers: usize,
        event_recv: R,
        event_send: S,
        event_need_key: K,
    ) -> Device<T, S, R, K> {
        // allocate shared device state
        let inner = Arc::new(DeviceInner {
            event_recv,
            event_send,
            event_need_key,
            parked: AtomicBool::new(false),
            running: AtomicBool::new(true),
            injector: Injector::new(),
            recv: spin::RwLock::new(HashMap::new()),
            ipv4: spin::RwLock::new(IpLookupTable::new()),
            ipv6: spin::RwLock::new(IpLookupTable::new()),
        });

        // alloacate work pool resources
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

    /// Adds a new peer to the device
    ///
    /// # Returns
    ///
    /// A atomic ref. counted peer (with liftime matching the device)
    pub fn new_peer(&self, opaque: T) -> Peer<T, S, R, K> {
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
