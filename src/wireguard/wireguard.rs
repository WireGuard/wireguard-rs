use super::constants::*;
use super::handshake;
use super::router;
use super::timers::{Events, Timers};

use super::bind::Reader as BindReader;
use super::bind::{Bind, Writer};
use super::tun::{Reader, Tun, MTU};
use super::Endpoint;

use hjul::Runner;

use std::fmt;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use std::collections::HashMap;

use log::debug;
use rand::rngs::OsRng;
use rand::Rng;
use spin::{Mutex, RwLock, RwLockReadGuard};

use byteorder::{ByteOrder, LittleEndian};
use crossbeam_channel::{bounded, Sender};
use x25519_dalek::{PublicKey, StaticSecret};

const SIZE_HANDSHAKE_QUEUE: usize = 128;
const THRESHOLD_UNDER_LOAD: usize = SIZE_HANDSHAKE_QUEUE / 4;
const DURATION_UNDER_LOAD: Duration = Duration::from_millis(10_000);

pub struct Peer<T: Tun, B: Bind> {
    pub router: Arc<router::Peer<B::Endpoint, Events<T, B>, T::Writer, B::Writer>>,
    pub state: Arc<PeerInner<B>>,
}

pub struct PeerInner<B: Bind> {
    // internal id (for logging)
    pub id: u64,

    // handshake state
    pub last_handshake_sent: Mutex<Instant>, // instant for last handshake
    pub handshake_queued: AtomicBool,        // is a handshake job currently queued for the peer?
    pub queue: Mutex<Sender<HandshakeJob<B::Endpoint>>>, // handshake queue

    // stats and configuration
    pub pk: PublicKey,          // public key, DISCUSS: avoid this. TODO: remove
    pub keepalive: AtomicUsize, // keepalive interval
    pub rx_bytes: AtomicU64,    // received bytes
    pub tx_bytes: AtomicU64,    // transmitted bytes

    // timer model
    pub timers: RwLock<Timers>,
}

pub struct WireguardInner<T: Tun, B: Bind> {
    // identifier (for logging)
    id: u32,
    start: Instant,

    // provides access to the MTU value of the tun device
    // (otherwise owned solely by the router and a dedicated read IO thread)
    mtu: T::MTU,
    send: RwLock<Option<B::Writer>>,

    // identify and configuration map
    peers: RwLock<HashMap<[u8; 32], Peer<T, B>>>,

    // cryptkey router
    router: router::Device<B::Endpoint, Events<T, B>, T::Writer, B::Writer>,

    // handshake related state
    handshake: RwLock<Handshake>,
    under_load: AtomicBool,
    pending: AtomicUsize, // num of pending handshake packets in queue
    queue: Mutex<Sender<HandshakeJob<B::Endpoint>>>,
}

pub enum HandshakeJob<E> {
    Message(Vec<u8>, E),
    New(PublicKey),
}

#[derive(Clone)]
pub struct WireguardHandle<T: Tun, B: Bind> {
    inner: Arc<WireguardInner<T, B>>,
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
}

impl<T: Tun, B: Bind> fmt::Display for Peer<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peer(id = {})", self.id)
    }
}

impl<T: Tun, B: Bind> fmt::Display for WireguardInner<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wireguard({:x})", self.id)
    }
}

impl<T: Tun, B: Bind> Deref for Peer<T, B> {
    type Target = PeerInner<B>;
    fn deref(&self) -> &Self::Target {
        &self.state
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

struct Handshake {
    device: handshake::Device,
    active: bool,
}

impl<T: Tun, B: Bind> Deref for WireguardHandle<T, B> {
    type Target = Arc<WireguardInner<T, B>>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct Wireguard<T: Tun, B: Bind> {
    runner: Runner,
    state: WireguardHandle<T, B>,
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
        let m = (a > b) as usize;
        a * m + (1 - m) * b
    }
    let pad = MESSAGE_PADDING_MULTIPLE;
    min(mtu, size + (pad - size % pad) % pad)
}

impl<T: Tun, B: Bind> Wireguard<T, B> {
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
        let mut handshake = self.state.handshake.write();
        match sk {
            None => {
                let mut rng = OsRng::new().unwrap();
                handshake.device.set_sk(StaticSecret::new(&mut rng));
                handshake.active = false;
            }
            Some(sk) => {
                handshake.device.set_sk(sk);
                handshake.active = true;
            }
        }
    }

    pub fn get_sk(&self) -> Option<StaticSecret> {
        let handshake = self.state.handshake.read();
        if handshake.active {
            Some(handshake.device.get_sk())
        } else {
            None
        }
    }

    pub fn new_peer(&self, pk: PublicKey) {
        let mut rng = OsRng::new().unwrap();
        let state = Arc::new(PeerInner {
            id: rng.gen(),
            pk,
            last_handshake_sent: Mutex::new(self.state.start - TIME_HORIZON),
            handshake_queued: AtomicBool::new(false),
            queue: Mutex::new(self.state.queue.lock().clone()),
            keepalive: AtomicUsize::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            timers: RwLock::new(Timers::dummy(&self.runner)),
        });

        // create a router peer
        let router = Arc::new(self.state.router.new_peer(state.clone()));

        // add to the handshake device
        self.state.handshake.write().device.add(pk).unwrap(); // TODO: handle adding of public key for interface

        // form WireGuard peer
        let peer = Peer { router, state };

        /* The need for dummy timers arises from the chicken-egg
         * problem of the timer callbacks being able to set timers themselves.
         *
         * This is in fact the only place where the write lock is ever taken.
         * TODO: Consider the ease of using atomic pointers instead.
         */
        *peer.timers.write() = Timers::new(&self.runner, peer.clone());

        // finally, add the peer to the wireguard device
        let mut peers = self.state.peers.write();
        peers.entry(*pk.as_bytes()).or_insert(peer);
    }

    /* Begin consuming messages from the reader.
     *
     * Any previous reader thread is stopped by closing the previous reader,
     * which unblocks the thread and causes an error on reader.read
     */
    pub fn add_reader(&self, reader: B::Reader) {
        let wg = self.state.clone();
        thread::spawn(move || {
            let mut last_under_load =
                Instant::now() - DURATION_UNDER_LOAD - Duration::from_millis(1000);

            loop {
                // create vector big enough for any message given current MTU
                let size = wg.mtu.mtu() + handshake::MAX_HANDSHAKE_MSG_SIZE;
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

                // message type de-multiplexer
                if msg.len() < std::mem::size_of::<u32>() {
                    continue;
                }
                match LittleEndian::read_u32(&msg[..]) {
                    handshake::TYPE_COOKIE_REPLY
                    | handshake::TYPE_INITIATION
                    | handshake::TYPE_RESPONSE => {
                        debug!("{} : reader, received handshake message", wg);

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

    pub fn new(mut readers: Vec<T::Reader>, writer: T::Writer, mtu: T::MTU) -> Wireguard<T, B> {
        // create device state
        let mut rng = OsRng::new().unwrap();
        let (tx, rx): (Sender<HandshakeJob<B::Endpoint>>, _) = bounded(SIZE_HANDSHAKE_QUEUE);
        let wg = Arc::new(WireguardInner {
            start: Instant::now(),
            id: rng.gen(),
            mtu: mtu.clone(),
            peers: RwLock::new(HashMap::new()),
            send: RwLock::new(None),
            router: router::Device::new(num_cpus::get(), writer), // router owns the writing half
            pending: AtomicUsize::new(0),
            handshake: RwLock::new(Handshake {
                device: handshake::Device::new(StaticSecret::new(&mut rng)),
                active: false,
            }),
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
                let mut rng = OsRng::new().unwrap();

                // process elements from the handshake queue
                for job in rx {
                    let state = wg.handshake.read();
                    if !state.active {
                        continue;
                    }

                    match job {
                        HandshakeJob::Message(msg, src) => {
                            wg.pending.fetch_sub(1, Ordering::SeqCst);

                            // feed message to handshake device
                            let src_validate = (&src).into_address(); // TODO avoid

                            // process message
                            match state.device.process(
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

                                            // update timers after sending handshake response
                                            if resp_len > 0 {
                                                debug!("{} : handshake worker, handshake response sent", wg);
                                                peer.state.sent_handshake_response();
                                            }

                                            // add resulting keypair to peer
                                            keypair.map(|kp| {
                                                debug!("{} : handshake worker, new keypair", wg);
                                                // free any unused ids
                                                for id in peer.router.add_keypair(kp) {
                                                    state.device.release(id);
                                                }
                                            });
                                        }
                                    }
                                }
                                Err(e) => debug!("{} : handshake worker, error = {:?}", wg, e),
                            }
                        }
                        HandshakeJob::New(pk) => {
                            debug!("{} : handshake worker, new handshake requested", wg);
                            let _ = state.device.begin(&mut rng, &pk).map(|msg| {
                                if let Some(peer) = wg.peers.read().get(pk.as_bytes()) {
                                    let _ = peer.router.send(&msg[..]).map_err(|e| {
                                        debug!("{} : handshake worker, failed to send handshake initiation, error = {}", wg, e)
                                    });
                                    peer.state.sent_handshake_initiation();
                                }
                            });
                        }
                    }
                }
            });
        }

        // start TUN read IO threads (multiple threads to support multi-queue interfaces)
        debug_assert!(
            readers.len() > 0,
            "attempted to create WG device without TUN readers"
        );
        while let Some(reader) = readers.pop() {
            let wg = wg.clone();
            let mtu = mtu.clone();
            thread::spawn(move || loop {
                // create vector big enough for any transport message (based on MTU)
                let mtu = mtu.mtu();
                let size = mtu + router::SIZE_MESSAGE_PREFIX;
                let mut msg: Vec<u8> = Vec::with_capacity(size + router::CAPACITY_MESSAGE_POSTFIX);
                msg.resize(size, 0);

                // read a new IP packet
                let payload = match reader.read(&mut msg[..], router::SIZE_MESSAGE_PREFIX) {
                    Ok(payload) => payload,
                    Err(e) => {
                        debug!("TUN worker, failed to read from tun device: {}", e);
                        return;
                    }
                };
                debug!("TUN worker, IP packet of {} bytes (MTU = {})", payload, mtu);

                // truncate padding
                let payload = padding(payload, mtu);
                msg.truncate(router::SIZE_MESSAGE_PREFIX + payload);
                debug_assert!(payload <= mtu);
                debug_assert_eq!(
                    if payload < mtu {
                        (msg.len() - router::SIZE_MESSAGE_PREFIX) % MESSAGE_PADDING_MULTIPLE
                    } else {
                        0
                    },
                    0
                );

                // crypt-key route
                let e = wg.router.send(msg);
                debug!("TUN worker, router returned {:?}", e);
            });
        }

        Wireguard {
            state: WireguardHandle { inner: wg },
            runner: Runner::new(TIMERS_TICK, TIMERS_SLOTS, TIMERS_CAPACITY),
        }
    }
}
