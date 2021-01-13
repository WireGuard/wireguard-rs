use super::constants::*;
use super::handshake;
use super::peer::PeerInner;
use super::router;
use super::timers::Timers;

use super::queue::ParallelQueue;
use super::workers::HandshakeJob;

use super::tun::Tun;
use super::udp::UDP;

use super::workers::{handshake_worker, tun_worker, udp_worker};

use std::fmt;
use std::thread;

use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex as StdMutex;
use std::time::Instant;

use rand::rngs::OsRng;
use rand::Rng;

use hjul::Runner;
use spin::{Mutex, RwLock};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct WireguardInner<T: Tun, B: UDP> {
    // identifier (for logging)
    pub id: u32,

    // timer wheel
    pub runner: Mutex<Runner>,

    // device enabled
    pub enabled: RwLock<bool>,

    // number of tun readers
    pub tun_readers: WaitCounter,

    // current MTU
    pub mtu: AtomicUsize,

    // peer map
    #[allow(clippy::type_complexity)]
    pub peers: RwLock<
        handshake::Device<router::PeerHandle<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer>>,
    >,

    // cryptokey router
    pub router: router::Device<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer>,

    // handshake related state
    pub last_under_load: Mutex<Instant>,
    pub pending: AtomicUsize, // number of pending handshake packets in queue
    pub queue: ParallelQueue<HandshakeJob<B::Endpoint>>,
}

pub struct WireGuard<T: Tun, B: UDP> {
    inner: Arc<WireguardInner<T, B>>,
}

pub struct WaitCounter(StdMutex<usize>, Condvar);

impl<T: Tun, B: UDP> fmt::Display for WireGuard<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wireguard({:x})", self.id)
    }
}

impl<T: Tun, B: UDP> Deref for WireGuard<T, B> {
    type Target = WireguardInner<T, B>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: Tun, B: UDP> Clone for WireGuard<T, B> {
    fn clone(&self) -> Self {
        WireGuard {
            inner: self.inner.clone(),
        }
    }
}

#[allow(clippy::mutex_atomic)]
impl WaitCounter {
    pub fn wait(&self) {
        let mut nread = self.0.lock().unwrap();
        while *nread > 0 {
            nread = self.1.wait(nread).unwrap();
        }
    }

    fn new() -> Self {
        Self(StdMutex::new(0), Condvar::new())
    }

    fn decrease(&self) {
        let mut nread = self.0.lock().unwrap();
        assert!(*nread > 0);
        *nread -= 1;
        if *nread == 0 {
            self.1.notify_all();
        }
    }

    fn increase(&self) {
        *self.0.lock().unwrap() += 1;
    }
}

impl<T: Tun, B: UDP> WireGuard<T, B> {
    /// Brings the WireGuard device down.
    /// Usually called when the associated interface is brought down.
    ///
    /// This stops any further action/timer on any peer
    /// and prevents transmission of further messages,
    /// however the device retrains its state.
    ///
    /// The instance will continue to consume and discard messages
    /// on both ends of the device.
    pub fn down(&self) {
        // ensure exclusive access (to avoid race with "up" call)
        let mut enabled = self.enabled.write();

        // check if already down
        if !(*enabled) {
            return;
        }

        // set mtu
        self.mtu.store(0, Ordering::Relaxed);

        // avoid transmission from router
        self.router.down();

        // set all peers down (stops timers)
        for (_, peer) in self.peers.write().iter() {
            peer.stop_timers();
            peer.down();
        }

        *enabled = false;
    }

    /// Brings the WireGuard device up.
    /// Usually called when the associated interface is brought up.
    pub fn up(&self, mtu: usize) {
        // ensure exclusive access (to avoid race with "up" call)
        let mut enabled = self.enabled.write();

        // set mtu
        self.mtu.store(mtu, Ordering::Relaxed);

        // check if already up
        if *enabled {
            return;
        }

        // enable transmission from router
        self.router.up();

        // set all peers up (restarts timers)
        for (_, peer) in self.peers.write().iter() {
            peer.up();
            peer.start_timers();
        }

        *enabled = true;
    }

    pub fn clear_peers(&self) {
        self.peers.write().clear();
    }

    pub fn remove_peer(&self, pk: &PublicKey) {
        let _ = self.peers.write().remove(pk);
    }

    pub fn set_key(&self, sk: Option<StaticSecret>) {
        let mut peers = self.peers.write();
        peers.set_sk(sk);
        self.router.clear_sending_keys();
    }

    pub fn get_sk(&self) -> Option<StaticSecret> {
        self.peers
            .read()
            .get_sk()
            .map(|sk| StaticSecret::from(sk.to_bytes()))
    }

    pub fn set_psk(&self, pk: PublicKey, psk: [u8; 32]) -> bool {
        self.peers.write().set_psk(pk, psk).is_ok()
    }
    pub fn get_psk(&self, pk: &PublicKey) -> Option<[u8; 32]> {
        self.peers.read().get_psk(pk).ok()
    }

    pub fn add_peer(&self, pk: PublicKey) -> bool {
        let mut peers = self.peers.write();
        if peers.contains_key(&pk) {
            return false;
        }

        // prevent up/down while inserting
        let enabled = self.enabled.read();

        // create timers (lookup by public key)
        let timers = Timers::new::<T, B>(self.clone(), pk, *enabled);

        // create new router peer
        let peer: router::PeerHandle<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer> =
            self.router.new_peer(PeerInner {
                id: OsRng.gen(),
                pk,
                wg: self.clone(),
                walltime_last_handshake: Mutex::new(None),
                last_handshake_sent: Mutex::new(Instant::now() - TIME_HORIZON),
                handshake_queued: AtomicBool::new(false),
                rx_bytes: AtomicU64::new(0),
                tx_bytes: AtomicU64::new(0),
                timers: RwLock::new(timers),
            });

        // finally, add the peer to the handshake device
        peers.add(pk, peer).is_ok()
    }

    /// Begin consuming messages from the reader.
    /// Multiple readers can be added to support multi-queue and individual Ipv6/Ipv4 sockets interfaces
    ///
    /// Any previous reader thread is stopped by closing the previous reader,
    /// which unblocks the thread and causes an error on reader.read
    pub fn add_udp_reader(&self, reader: B::Reader) {
        let wg = self.clone();
        thread::spawn(move || {
            udp_worker(&wg, reader);
        });
    }

    pub fn set_writer(&self, writer: B::Writer) {
        self.router.set_outbound_writer(writer);
    }

    pub fn add_tun_reader(&self, reader: T::Reader) {
        let wg = self.clone();

        // increment reader count
        wg.tun_readers.increase();

        // start worker
        thread::spawn(move || {
            tun_worker(&wg, reader);
            wg.tun_readers.decrease();
        });
    }

    pub fn wait(&self) {
        self.tun_readers.wait();
    }

    pub fn new(writer: T::Writer) -> WireGuard<T, B> {
        // workers equal to number of physical cores
        let cpus = num_cpus::get();

        // create handshake queue
        let (tx, mut rxs) = ParallelQueue::new(cpus, 128);

        // create router
        let router: router::Device<B::Endpoint, PeerInner<T, B>, T::Writer, B::Writer> =
            router::Device::new(num_cpus::get(), writer);

        // create arc to state
        let wg = WireGuard {
            inner: Arc::new(WireguardInner {
                enabled: RwLock::new(false),
                tun_readers: WaitCounter::new(),
                id: OsRng.gen(),
                mtu: AtomicUsize::new(0),
                last_under_load: Mutex::new(Instant::now() - TIME_HORIZON),
                router,
                pending: AtomicUsize::new(0),
                peers: RwLock::new(handshake::Device::new()),
                runner: Mutex::new(Runner::new(TIMERS_TICK, TIMERS_SLOTS, TIMERS_CAPACITY)),
                queue: tx,
            }),
        };

        // start handshake workers
        while let Some(rx) = rxs.pop() {
            let wg = wg.clone();
            thread::spawn(move || handshake_worker(&wg, rx));
        }

        wg
    }
}
