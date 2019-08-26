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

use super::types::{Callback, Opaque};

pub struct DeviceInner<T: Opaque> {
    // callbacks (used for timers)
    pub event_recv: Box<dyn Callback<T>>, // authenticated message received
    pub event_send: Box<dyn Callback<T>>, // authenticated message send
    pub event_new_handshake: (),          // called when a new handshake is required

    pub stopped: AtomicBool,
    pub injector: Injector<()>, // parallel enc/dec task injector
    pub threads: Vec<thread::JoinHandle<()>>, // join handles of worker threads
    pub recv: spin::RwLock<HashMap<u32, DecryptionState<T>>>, // receiver id -> decryption state
    pub ipv4: spin::RwLock<IpLookupTable<Ipv4Addr, Weak<PeerInner<T>>>>, // ipv4 cryptkey routing
    pub ipv6: spin::RwLock<IpLookupTable<Ipv6Addr, Weak<PeerInner<T>>>>, // ipv6 cryptkey routing
}

pub struct EncryptionState {
    pub key: [u8; 32], // encryption key
    pub id: u32,       // sender id
    pub nonce: u64,    // next available nonce
    pub death: Instant, // time when the key no longer can be used for encryption
                       // (birth + reject-after-time - keepalive-timeout - rekey-timeout)
}

pub struct DecryptionState<T: Opaque> {
    pub key: [u8; 32],
    pub keypair: Weak<KeyPair>,
    pub protector: spin::Mutex<AntiReplay>,
    pub peer: Weak<PeerInner<T>>,
    pub death: Instant, // time when the key can no longer be used for decryption
}

pub struct Device<T: Opaque>(Arc<DeviceInner<T>>);

impl<T: Opaque> Drop for Device<T> {
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

impl<T: Opaque> Device<T> {
    pub fn new<F1: Callback<T>, F2: Callback<T>>(
        workers: usize,
        event_recv: F1,
        event_send: F2,
    ) -> Device<T> {
        Device(Arc::new(DeviceInner {
            event_recv: Box::new(event_recv),
            event_send: Box::new(event_send),
            event_new_handshake: (),
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
    pub fn new_peer(&self, opaque: T) -> Peer<T> {
        peer::new_peer(self.0.clone(), opaque)
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
    pub fn send(&self, pt_msg: &mut [u8]) -> Arc<Peer<T>> {
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
