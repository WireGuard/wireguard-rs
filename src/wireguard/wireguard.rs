use super::constants::*;
use super::handshake;
use super::router;
use super::timers::{Events, Timers};
use super::{Peer, PeerInner};

use super::tun;
use super::tun::Reader as TunReader;

use super::udp;
use super::udp::Reader as UDPReader;
use super::udp::Writer as UDPWriter;

use super::Endpoint;

use hjul::Runner;

use std::fmt;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// TODO: avoid
use std::sync::Condvar;
use std::sync::Mutex as StdMutex;

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use log::debug;
use rand::rngs::OsRng;
use rand::Rng;
use spin::{Mutex, RwLock};

use byteorder::{ByteOrder, LittleEndian};
use crossbeam_channel::{bounded, Sender};
use x25519_dalek::{PublicKey, StaticSecret};

const SIZE_HANDSHAKE_QUEUE: usize = 128;
const THRESHOLD_UNDER_LOAD: usize = SIZE_HANDSHAKE_QUEUE / 4;
const DURATION_UNDER_LOAD: Duration = Duration::from_millis(10_000);

#[derive(Clone)]
pub struct WaitHandle(Arc<(StdMutex<usize>, Condvar)>);

impl WaitHandle {
    pub fn wait(&self) {
        let (lock, cvar) = &*self.0;
        let mut nread = lock.lock().unwrap();
        while *nread > 0 {
            nread = cvar.wait(nread).unwrap();
        }
    }

    fn new() -> Self {
        Self(Arc::new((StdMutex::new(0), Condvar::new())))
    }

    fn decrease(&self) {
        let (lock, cvar) = &*self.0;
        let mut nread = lock.lock().unwrap();
        assert!(*nread > 0);
        *nread -= 1;
        cvar.notify_all();
    }

    fn increase(&self) {
        let (lock, _) = &*self.0;
        let mut nread = lock.lock().unwrap();
        *nread += 1;
    }
}

pub struct WireguardInner<T: tun::Tun, B: udp::UDP> {
    // identifier (for logging)
    id: u32,

    // device enabled
    enabled: RwLock<bool>,

    // enables waiting for all readers to finish
    tun_readers: WaitHandle,

    // current MTU
    mtu: AtomicUsize,

    // outbound writer
    send: RwLock<Option<B::Writer>>,

    // identity and configuration map
    peers: RwLock<HashMap<[u8; 32], Peer<T, B>>>,

    // cryptokey router
    router: router::Device<B::Endpoint, Events<T, B>, T::Writer, B::Writer>,

    // handshake related state
    handshake: RwLock<handshake::Device>,
    under_load: AtomicBool,
    pending: AtomicUsize, // num of pending handshake packets in queue
    queue: Mutex<Sender<HandshakeJob<B::Endpoint>>>,
}

impl<T: tun::Tun, B: udp::UDP> PeerInner<T, B> {
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
            self.wg.pending.fetch_add(1, Ordering::SeqCst);
            self.queue.lock().send(HandshakeJob::New(self.pk)).unwrap();
        }
    }
}

pub enum HandshakeJob<E> {
    Message(Vec<u8>, E),
    New(PublicKey),
}

impl<T: tun::Tun, B: udp::UDP> fmt::Display for WireguardInner<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wireguard({:x})", self.id)
    }
}

impl<T: tun::Tun, B: udp::UDP> Deref for Wireguard<T, B> {
    type Target = Arc<WireguardInner<T, B>>;
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

pub struct Wireguard<T: tun::Tun, B: udp::UDP> {
    runner: Runner,
    state: Arc<WireguardInner<T, B>>,
}

/* Returns the padded length of a message:
 *
 * # Arguments
 *
 * - `size` : Size of unpadded message
 * - `mtu` : Maximum transmission unit of the device
 *
 * # Returns
 *
 * The padded length (always less than or equal to the MTU)
 */
#[inline(always)]
const fn padding(size: usize, mtu: usize) -> usize {
    #[inline(always)]
    const fn min(a: usize, b: usize) -> usize {
        let m = (a < b) as usize;
        a * m + (1 - m) * b
    }
    let pad = MESSAGE_PADDING_MULTIPLE;
    min(mtu, size + (pad - size % pad) % pad)
}

impl<T: tun::Tun, B: udp::UDP> Wireguard<T, B> {
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
        if *enabled == false {
            return;
        }

        // set mtu
        self.state.mtu.store(0, Ordering::Relaxed);

        // avoid tranmission from router
        self.router.down();

        // set all peers down (stops timers)
        for peer in self.peers.write().values() {
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
        self.state.mtu.store(mtu, Ordering::Relaxed);

        // check if already up
        if *enabled {
            return;
        }

        // enable tranmission from router
        self.router.up();

        // set all peers up (restarts timers)
        for peer in self.peers.write().values() {
            peer.up();
        }

        *enabled = true;
    }

    pub fn clear_peers(&self) {
        self.state.peers.write().clear();
    }

    pub fn remove_peer(&self, pk: &PublicKey) {
        self.state.peers.write().remove(pk.as_bytes());
    }

    pub fn lookup_peer(&self, pk: &PublicKey) -> Option<Peer<T, B>> {
        self.state
            .peers
            .read()
            .get(pk.as_bytes())
            .map(|p| p.clone())
    }

    pub fn list_peers(&self) -> Vec<Peer<T, B>> {
        let peers = self.state.peers.read();
        let mut list = Vec::with_capacity(peers.len());
        for (k, v) in peers.iter() {
            debug_assert!(k == v.pk.as_bytes());
            list.push(v.clone());
        }
        list
    }

    pub fn set_key(&self, sk: Option<StaticSecret>) {
        self.handshake.write().set_sk(sk);
    }

    pub fn get_sk(&self) -> Option<StaticSecret> {
        self.handshake
            .read()
            .get_sk()
            .map(|sk| StaticSecret::from(sk.to_bytes()))
    }

    pub fn set_psk(&self, pk: PublicKey, psk: [u8; 32]) -> bool {
        self.state.handshake.write().set_psk(pk, psk).is_ok()
    }
    pub fn get_psk(&self, pk: &PublicKey) -> Option<[u8; 32]> {
        self.state.handshake.read().get_psk(pk).ok()
    }

    pub fn add_peer(&self, pk: PublicKey) -> bool {
        if self.state.peers.read().contains_key(pk.as_bytes()) {
            return false;
        }

        let mut rng = OsRng::new().unwrap();
        let state = Arc::new(PeerInner {
            id: rng.gen(),
            pk,
            wg: self.state.clone(),
            walltime_last_handshake: Mutex::new(None),
            last_handshake_sent: Mutex::new(Instant::now() - TIME_HORIZON),
            handshake_queued: AtomicBool::new(false),
            queue: Mutex::new(self.state.queue.lock().clone()),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            timers: RwLock::new(Timers::dummy(&self.runner)),
        });

        // create a router peer
        let router = Arc::new(self.state.router.new_peer(state.clone()));

        // form WireGuard peer
        let peer = Peer { router, state };

        // finally, add the peer to the wireguard device
        let mut peers = self.state.peers.write();
        match peers.entry(*pk.as_bytes()) {
            Entry::Occupied(_) => false,
            Entry::Vacant(vacancy) => {
                // check that the public key does not cause conflict with the private key of the device
                let ok_pk = self.state.handshake.write().add(pk).is_ok();
                if !ok_pk {
                    return false;
                }

                // prevent up/down while inserting
                let enabled = self.enabled.read();

                /* The need for dummy timers arises from the chicken-egg
                 * problem of the timer callbacks being able to set timers themselves.
                 *
                 * This is in fact the only place where the write lock is ever taken.
                 * TODO: Consider the ease of using atomic pointers instead.
                 */
                *peer.timers.write() = Timers::new(&self.runner, *enabled, peer.clone());

                // insert into peer map (takes ownership and ensures that the peer is not dropped)
                vacancy.insert(peer);
                true
            }
        }
    }

    /// Begin consuming messages from the reader.
    /// Multiple readers can be added to support multi-queue and individual Ipv6/Ipv4 sockets interfaces
    ///
    /// Any previous reader thread is stopped by closing the previous reader,
    /// which unblocks the thread and causes an error on reader.read
    pub fn add_udp_reader(&self, reader: B::Reader) {
        let wg = self.state.clone();
        thread::spawn(move || {
            let mut last_under_load =
                Instant::now() - DURATION_UNDER_LOAD - Duration::from_millis(1000);

            loop {
                // create vector big enough for any message given current MTU
                let mtu = wg.mtu.load(Ordering::Relaxed);
                let size = mtu + handshake::MAX_HANDSHAKE_MSG_SIZE;
                let mut msg: Vec<u8> = Vec::with_capacity(size);
                msg.resize(size, 0);

                // read UDP packet into vector
                let (size, src) = match reader.read(&mut msg) {
                    Err(e) => {
                        debug!("Bind reader closed with {}", e);
                        return;
                    }
                    Ok(v) => v,
                };
                msg.truncate(size);

                // TODO: start device down
                if mtu == 0 {
                    continue;
                }

                // message type de-multiplexer
                if msg.len() < std::mem::size_of::<u32>() {
                    continue;
                }
                match LittleEndian::read_u32(&msg[..]) {
                    handshake::TYPE_COOKIE_REPLY
                    | handshake::TYPE_INITIATION
                    | handshake::TYPE_RESPONSE => {
                        debug!("{} : reader, received handshake message", wg);

                        // add one to pending
                        let pending = wg.pending.fetch_add(1, Ordering::SeqCst);

                        // update under_load flag
                        if pending > THRESHOLD_UNDER_LOAD {
                            debug!("{} : reader, set under load (pending = {})", wg, pending);
                            last_under_load = Instant::now();
                            wg.under_load.store(true, Ordering::SeqCst);
                        } else if last_under_load.elapsed() > DURATION_UNDER_LOAD {
                            debug!("{} : reader, clear under load", wg);
                            wg.under_load.store(false, Ordering::SeqCst);
                        }

                        // add to handshake queue
                        wg.queue
                            .lock()
                            .send(HandshakeJob::Message(msg, src))
                            .unwrap();
                    }
                    router::TYPE_TRANSPORT => {
                        debug!("{} : reader, received transport message", wg);

                        // transport message
                        let _ = wg.router.recv(src, msg).map_err(|e| {
                            debug!("Failed to handle incoming transport message: {}", e);
                        });
                    }
                    _ => (),
                }
            }
        });
    }

    pub fn set_writer(&self, writer: B::Writer) {
        // TODO: Consider unifying these and avoid Clone requirement on writer
        *self.state.send.write() = Some(writer.clone());
        self.state.router.set_outbound_writer(writer);
    }

    pub fn add_tun_reader(&self, reader: T::Reader) {
        fn worker<T: tun::Tun, B: udp::UDP>(wg: &Arc<WireguardInner<T, B>>, reader: T::Reader) {
            loop {
                // create vector big enough for any transport message (based on MTU)
                let mtu = wg.mtu.load(Ordering::Relaxed);
                let size = mtu + router::SIZE_MESSAGE_PREFIX + 1;
                let mut msg: Vec<u8> = Vec::with_capacity(size + router::CAPACITY_MESSAGE_POSTFIX);
                msg.resize(size, 0);

                // read a new IP packet
                let payload = match reader.read(&mut msg[..], router::SIZE_MESSAGE_PREFIX) {
                    Ok(payload) => payload,
                    Err(e) => {
                        debug!("TUN worker, failed to read from tun device: {}", e);
                        break;
                    }
                };
                debug!("TUN worker, IP packet of {} bytes (MTU = {})", payload, mtu);

                // TODO: start device down
                if mtu == 0 {
                    continue;
                }

                // truncate padding
                let padded = padding(payload, mtu);
                log::trace!(
                    "TUN worker, payload length = {}, padded length = {}",
                    payload,
                    padded
                );
                msg.truncate(router::SIZE_MESSAGE_PREFIX + padded);
                debug_assert!(padded <= mtu);
                debug_assert_eq!(
                    if padded < mtu {
                        (msg.len() - router::SIZE_MESSAGE_PREFIX) % MESSAGE_PADDING_MULTIPLE
                    } else {
                        0
                    },
                    0
                );

                // crypt-key route
                let e = wg.router.send(msg);
                debug!("TUN worker, router returned {:?}", e);
            }
        }

        // start a thread for every reader
        let wg = self.state.clone();

        // increment reader count
        wg.tun_readers.increase();

        // start worker
        thread::spawn(move || {
            worker(&wg, reader);
            wg.tun_readers.decrease();
        });
    }

    pub fn wait(&self) -> WaitHandle {
        self.state.tun_readers.clone()
    }

    pub fn new(writer: T::Writer) -> Wireguard<T, B> {
        // create device state
        let mut rng = OsRng::new().unwrap();

        // handshake queue
        let (tx, rx): (Sender<HandshakeJob<B::Endpoint>>, _) = bounded(SIZE_HANDSHAKE_QUEUE);

        let wg = Arc::new(WireguardInner {
            enabled: RwLock::new(false),
            tun_readers: WaitHandle::new(),
            id: rng.gen(),
            mtu: AtomicUsize::new(0),
            peers: RwLock::new(HashMap::new()),
            send: RwLock::new(None),
            router: router::Device::new(num_cpus::get(), writer), // router owns the writing half
            pending: AtomicUsize::new(0),
            handshake: RwLock::new(handshake::Device::new()),
            under_load: AtomicBool::new(false),
            queue: Mutex::new(tx),
        });

        // start handshake workers
        for _ in 0..num_cpus::get() {
            let wg = wg.clone();
            let rx = rx.clone();
            thread::spawn(move || {
                debug!("{} : handshake worker, started", wg);

                // prepare OsRng instance for this thread
                let mut rng = OsRng::new().expect("Unable to obtain a CSPRNG");

                // process elements from the handshake queue
                for job in rx {
                    // decrement pending
                    wg.pending.fetch_sub(1, Ordering::SeqCst);

                    let device = wg.handshake.read();
                    match job {
                        HandshakeJob::Message(msg, src) => {
                            // feed message to handshake device
                            let src_validate = (&src).into_address(); // TODO avoid

                            // process message
                            match device.process(
                                &mut rng,
                                &msg[..],
                                if wg.under_load.load(Ordering::Relaxed) {
                                    debug!("{} : handshake worker, under load", wg);
                                    Some(&src_validate)
                                } else {
                                    None
                                },
                            ) {
                                Ok((pk, resp, keypair)) => {
                                    // send response (might be cookie reply or handshake response)
                                    let mut resp_len: u64 = 0;
                                    if let Some(msg) = resp {
                                        resp_len = msg.len() as u64;
                                        let send: &Option<B::Writer> = &*wg.send.read();
                                        if let Some(writer) = send.as_ref() {
                                            debug!(
                                                "{} : handshake worker, send response ({} bytes)",
                                                wg, resp_len
                                            );
                                            let _ = writer.write(&msg[..], &src).map_err(|e| {
                                                debug!(
                                                    "{} : handshake worker, failed to send response, error = {}",
                                                    wg,
                                                    e
                                                )
                                            });
                                        }
                                    }

                                    // update peer state
                                    if let Some(pk) = pk {
                                        // authenticated handshake packet received
                                        if let Some(peer) = wg.peers.read().get(pk.as_bytes()) {
                                            // add to rx_bytes and tx_bytes
                                            let req_len = msg.len() as u64;
                                            peer.rx_bytes.fetch_add(req_len, Ordering::Relaxed);
                                            peer.tx_bytes.fetch_add(resp_len, Ordering::Relaxed);

                                            // update endpoint
                                            peer.router.set_endpoint(src);

                                            if resp_len > 0 {
                                                // update timers after sending handshake response
                                                debug!("{} : handshake worker, handshake response sent", wg);
                                                peer.state.sent_handshake_response();
                                            } else {
                                                // update timers after receiving handshake response
                                                debug!("{} : handshake worker, handshake response was received", wg);
                                                peer.state.timers_handshake_complete();
                                            }

                                            // add any new keypair to peer
                                            keypair.map(|kp| {
                                                debug!(
                                                    "{} : handshake worker, new keypair for {}",
                                                    wg, peer
                                                );

                                                // this means that a handshake response was processed or sent
                                                peer.timers_session_derieved();

                                                // free any unused ids
                                                for id in peer.router.add_keypair(kp) {
                                                    device.release(id);
                                                }
                                            });
                                        }
                                    }
                                }
                                Err(e) => debug!("{} : handshake worker, error = {:?}", wg, e),
                            }
                        }
                        HandshakeJob::New(pk) => {
                            if let Some(peer) = wg.peers.read().get(pk.as_bytes()) {
                                debug!(
                                    "{} : handshake worker, new handshake requested for {}",
                                    wg, peer
                                );
                                let _ = device.begin(&mut rng, &peer.pk).map(|msg| {
                                    let _ = peer.router.send(&msg[..]).map_err(|e| {
                                        debug!("{} : handshake worker, failed to send handshake initiation, error = {}", wg, e)
                                    });
                                    peer.state.sent_handshake_initiation();
                                });
                                peer.handshake_queued.store(false, Ordering::SeqCst);
                            }
                        }
                    }
                }
            });
        }

        Wireguard {
            state: wg,
            runner: Runner::new(TIMERS_TICK, TIMERS_SLOTS, TIMERS_CAPACITY),
        }
    }
}
