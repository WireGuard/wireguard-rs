use crate::constants::*;
use crate::handshake;
use crate::router;
use crate::timers::{Events, Timers};
use crate::types::{Bind, Endpoint, Tun};

use hjul::Runner;

use std::cmp;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use std::collections::HashMap;

use log::debug;
use rand::rngs::OsRng;
use spin::{Mutex, RwLock};

use byteorder::{ByteOrder, LittleEndian};
use crossbeam_channel::{bounded, Sender};
use x25519_dalek::{PublicKey, StaticSecret};

const SIZE_HANDSHAKE_QUEUE: usize = 128;
const THRESHOLD_UNDER_LOAD: usize = SIZE_HANDSHAKE_QUEUE / 4;
const DURATION_UNDER_LOAD: Duration = Duration::from_millis(10_000);

#[derive(Clone)]
pub struct Peer<T: Tun, B: Bind> {
    pub router: Arc<router::Peer<Events<T, B>, T, B>>,
    pub state: Arc<PeerInner<B>>,
}

pub struct PeerInner<B: Bind> {
    pub keepalive: AtomicUsize, // keepalive interval
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub queue: Mutex<Sender<HandshakeJob<B::Endpoint>>>, // handshake queue
    pub pk: PublicKey, // DISCUSS: Change layout in handshake module (adopt pattern of router), to avoid this.
    pub timers: RwLock<Timers>, //
}

impl<T: Tun, B: Bind> Deref for Peer<T, B> {
    type Target = PeerInner<B>;
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<B: Bind> PeerInner<B> {
    pub fn new_handshake(&self) {
        self.queue.lock().send(HandshakeJob::New(self.pk)).unwrap();
    }
}

struct Handshake {
    device: handshake::Device,
    active: bool,
}

pub enum HandshakeJob<E> {
    Message(Vec<u8>, E),
    New(PublicKey),
}

struct WireguardInner<T: Tun, B: Bind> {
    // identify and configuration map
    peers: RwLock<HashMap<[u8; 32], Peer<T, B>>>,

    // cryptkey router
    router: router::Device<Events<T, B>, T, B>,

    // handshake related state
    handshake: RwLock<Handshake>,
    under_load: AtomicBool,
    pending: AtomicUsize, // num of pending handshake packets in queue
    queue: Mutex<Sender<HandshakeJob<B::Endpoint>>>,

    // IO
    bind: B,
}

pub struct Wireguard<T: Tun, B: Bind> {
    runner: Runner,
    state: Arc<WireguardInner<T, B>>,
}

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

    pub fn new_peer(&self, pk: PublicKey) -> Peer<T, B> {
        let state = Arc::new(PeerInner {
            pk,
            queue: Mutex::new(self.state.queue.lock().clone()),
            keepalive: AtomicUsize::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            timers: RwLock::new(Timers::dummy(&self.runner)),
        });

        let router = Arc::new(self.state.router.new_peer(state.clone()));

        let peer = Peer { router, state };

        /* The need for dummy timers arises from the chicken-egg
         * problem of the timer callbacks being able to set timers themselves.
         *
         * This is in fact the only place where the write lock is ever taken.
         */
        *peer.timers.write() = Timers::new(&self.runner, peer.clone());
        peer
    }

    pub fn new(tun: T, bind: B) -> Wireguard<T, B> {
        // create device state
        let mut rng = OsRng::new().unwrap();
        let (tx, rx): (Sender<HandshakeJob<B::Endpoint>>, _) = bounded(SIZE_HANDSHAKE_QUEUE);
        let wg = Arc::new(WireguardInner {
            peers: RwLock::new(HashMap::new()),
            router: router::Device::new(num_cpus::get(), tun.clone(), bind.clone()),
            pending: AtomicUsize::new(0),
            handshake: RwLock::new(Handshake {
                device: handshake::Device::new(StaticSecret::new(&mut rng)),
                active: false,
            }),
            under_load: AtomicBool::new(false),
            bind: bind.clone(),
            queue: Mutex::new(tx),
        });

        // start handshake workers
        for _ in 0..num_cpus::get() {
            let wg = wg.clone();
            let rx = rx.clone();
            let bind = bind.clone();
            thread::spawn(move || {
                // prepare OsRng instance for this thread
                let mut rng = OsRng::new().unwrap();

                // process elements from the handshake queue
                for job in rx {
                    wg.pending.fetch_sub(1, Ordering::SeqCst);
                    let state = wg.handshake.read();
                    if !state.active {
                        continue;
                    }

                    match job {
                        HandshakeJob::Message(msg, src) => {
                            // feed message to handshake device
                            let src_validate = (&src).into_address(); // TODO avoid

                            // process message
                            match state.device.process(
                                &mut rng,
                                &msg[..],
                                if wg.under_load.load(Ordering::Relaxed) {
                                    Some(&src_validate)
                                } else {
                                    None
                                },
                            ) {
                                Ok((pk, msg, keypair)) => {
                                    // send response
                                    if let Some(msg) = msg {
                                        let _ = bind.send(&msg[..], &src).map_err(|e| {
                                            debug!(
                                        "handshake worker, failed to send response, error = {:?}",
                                        e
                                    )
                                        });
                                    }

                                    // update timers
                                    if let Some(pk) = pk {
                                        if let Some(peer) = wg.peers.read().get(pk.as_bytes()) {
                                            // update endpoint (DISCUSS: right semantics?)
                                            peer.router.set_endpoint(src_validate);

                                            // add keypair to peer and free any unused ids
                                            if let Some(keypair) = keypair {
                                                for id in peer.router.add_keypair(keypair) {
                                                    state.device.release(id);
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => debug!("handshake worker, error = {:?}", e),
                            }
                        }
                        HandshakeJob::New(pk) => {
                            let msg = state.device.begin(&mut rng, &pk).unwrap(); // TODO handle
                            if let Some(peer) = wg.peers.read().get(pk.as_bytes()) {
                                peer.router.send(&msg[..]);
                                peer.timers.read().handshake_sent();
                            }
                        }
                    }
                }
            });
        }

        // start UDP read IO thread
        {
            let wg = wg.clone();
            let tun = tun.clone();
            let bind = bind.clone();
            thread::spawn(move || {
                let mut last_under_load =
                    Instant::now() - DURATION_UNDER_LOAD - Duration::from_millis(1000);

                loop {
                    // create vector big enough for any message given current MTU
                    let size = tun.mtu() + handshake::MAX_HANDSHAKE_MSG_SIZE;
                    let mut msg: Vec<u8> = Vec::with_capacity(size);
                    msg.resize(size, 0);

                    // read UDP packet into vector
                    let (size, src) = bind.recv(&mut msg).unwrap(); // TODO handle error
                    msg.truncate(size);

                    // message type de-multiplexer
                    if msg.len() < std::mem::size_of::<u32>() {
                        continue;
                    }
                    match LittleEndian::read_u32(&msg[..]) {
                        handshake::TYPE_COOKIE_REPLY
                        | handshake::TYPE_INITIATION
                        | handshake::TYPE_RESPONSE => {
                            // update under_load flag
                            if wg.pending.fetch_add(1, Ordering::SeqCst) > THRESHOLD_UNDER_LOAD {
                                last_under_load = Instant::now();
                                wg.under_load.store(true, Ordering::SeqCst);
                            } else if last_under_load.elapsed() > DURATION_UNDER_LOAD {
                                wg.under_load.store(false, Ordering::SeqCst);
                            }

                            wg.queue
                                .lock()
                                .send(HandshakeJob::Message(msg, src))
                                .unwrap();
                        }
                        router::TYPE_TRANSPORT => {
                            // transport message
                            let _ = wg.router.recv(src, msg);
                        }
                        _ => (),
                    }
                }
            });
        }

        // start TUN read IO thread
        {
            let wg = wg.clone();
            thread::spawn(move || loop {
                // create vector big enough for any transport message (based on MTU)
                let mtu = tun.mtu();
                let size = mtu + router::SIZE_MESSAGE_PREFIX;
                let mut msg: Vec<u8> = Vec::with_capacity(size + router::CAPACITY_MESSAGE_POSTFIX);
                msg.resize(size, 0);

                // read a new IP packet
                let payload = tun.read(&mut msg[..], router::SIZE_MESSAGE_PREFIX).unwrap();
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
            state: wg,
            runner: Runner::new(TIMERS_TICK, TIMERS_SLOTS, TIMERS_CAPACITY),
        }
    }
}
