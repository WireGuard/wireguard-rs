use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::Instant;

use crossbeam_deque::{Injector, Steal};
use spin;
use treebitmap::IpLookupTable;

use super::super::types::KeyPair;
use super::anti_replay::AntiReplay;
use super::peer;
use super::peer::{Peer, PeerInner};

use super::types::{Callback, KeyCallback, Opaque};

pub struct DeviceInner<T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>> {
    // threading and workers
    pub stopped: AtomicBool,
    pub injector: Injector<()>, // parallel enc/dec task injector
    pub threads: Vec<thread::JoinHandle<()>>, // join handles of worker threads

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
);

impl<T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>> Drop for Device<T, S, R, K> {
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

impl<T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>> Device<T, S, R, K> {
    pub fn new(
        workers: usize,
        event_recv: R,
        event_send: S,
        event_need_key: K,
    ) -> Device<T, S, R, K> {
        Device(Arc::new(DeviceInner {
            event_recv,
            event_send,
            event_need_key,
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
