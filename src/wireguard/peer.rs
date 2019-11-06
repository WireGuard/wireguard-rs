use super::constants::*;
use super::router;
use super::timers::{Events, Timers};
use super::HandshakeJob;

use super::bind::Bind;
use super::tun::Tun;

use std::fmt;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use spin::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crossbeam_channel::Sender;
use x25519_dalek::PublicKey;

pub struct Peer<T: Tun, B: Bind> {
    pub router: Arc<router::Peer<B::Endpoint, Events<T, B>, T::Writer, B::Writer>>,
    pub state: Arc<PeerInner<B>>,
}

pub struct PeerInner<B: Bind> {
    // internal id (for logging)
    pub id: u64,

    // handshake state
    pub walltime_last_handshake: Mutex<SystemTime>,
    pub last_handshake_sent: Mutex<Instant>, // instant for last handshake
    pub handshake_queued: AtomicBool,        // is a handshake job currently queued for the peer?
    pub queue: Mutex<Sender<HandshakeJob<B::Endpoint>>>, // handshake queue

    // stats and configuration
    pub pk: PublicKey,       // public key, DISCUSS: avoid this. TODO: remove
    pub rx_bytes: AtomicU64, // received bytes
    pub tx_bytes: AtomicU64, // transmitted bytes

    // timer model
    pub timers: RwLock<Timers>,
}

impl<T: Tun, B: Bind> Clone for Peer<T, B> {
    fn clone(&self) -> Peer<T, B> {
        Peer {
            router: self.router.clone(),
            state: self.state.clone(),
        }
    }
}

impl<B: Bind> PeerInner<B> {
    #[inline(always)]
    pub fn timers(&self) -> RwLockReadGuard<Timers> {
        self.timers.read()
    }

    #[inline(always)]
    pub fn timers_mut(&self) -> RwLockWriteGuard<Timers> {
        self.timers.write()
    }
}

impl<T: Tun, B: Bind> fmt::Display for Peer<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peer(id = {})", self.id)
    }
}

impl<T: Tun, B: Bind> Deref for Peer<T, B> {
    type Target = PeerInner<B>;
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<T: Tun, B: Bind> Peer<T, B> {
    /// Bring the peer down. Causing:
    ///
    /// - Timers to be stopped and disabled.
    /// - All keystate to be zeroed
    pub fn down(&self) {
        self.stop_timers();
        self.router.down();
    }

    /// Bring the peer up.
    pub fn up(&self) {
        self.router.up();
        self.start_timers();
    }
}

impl<B: Bind> PeerInner<B> {
    /* Queue a handshake request for the parallel workers
     * (if one does not already exist)
     *
     * The function is ratelimited.
     */
    pub fn packet_send_handshake_initiation(&self) {
        // the function is rate limited

        {
            let mut lhs = self.last_handshake_sent.lock();
            if lhs.elapsed() < REKEY_TIMEOUT {
                return;
            }
            *lhs = Instant::now();
        }

        // create a new handshake job for the peer

        if !self.handshake_queued.swap(true, Ordering::SeqCst) {
            self.queue.lock().send(HandshakeJob::New(self.pk)).unwrap();
        }
    }
}
