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
use super::peer;
use super::peer::{Peer, PeerInner};
use super::workers;

pub struct DeviceInner {
    pub stopped: AtomicBool,
    pub injector: Injector<()>, // parallel enc/dec task injector
    pub threads: Vec<thread::JoinHandle<()>>, // join handles of worker threads
    pub recv: spin::RwLock<HashMap<u32, DecryptionState>>, // receiver id -> decryption state
    pub ipv4: spin::RwLock<IpLookupTable<Ipv4Addr, Weak<PeerInner>>>, // ipv4 cryptkey routing
    pub ipv6: spin::RwLock<IpLookupTable<Ipv6Addr, Weak<PeerInner>>>, // ipv6 cryptkey routing
}

pub struct EncryptionState {
    pub key: [u8; 32], // encryption key
    pub id: u32,       // sender id
    pub nonce: u64,    // next available nonce
    pub death: Instant, // time when the key no longer can be used for encryption
                       // (birth + reject-after-time - keepalive-timeout - rekey-timeout)
}

pub struct DecryptionState {
    pub key: [u8; 32],
    pub keypair: Weak<KeyPair>,
    pub protector: spin::Mutex<AntiReplay>,
    pub peer: Weak<PeerInner>,
    pub death: Instant, // time when the key can no longer be used for decryption
}

pub struct Device(Arc<DeviceInner>);

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
        peer::new_peer(self.0.clone())
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

    /// Receive an encrypted transport message
    ///
    /// # Arguments
    ///
    /// - ct_msg: Encrypted transport message
    pub fn recv(&self, ct_msg: &mut [u8]) {
        unimplemented!();
    }
}
