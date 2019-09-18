use crate::handshake;
use crate::router;
use crate::types::{Bind, Endpoint, Tun};

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
pub struct Peer<T: Tun, B: Bind>(Arc<PeerInner<T, B>>);

pub struct PeerInner<T: Tun, B: Bind> {
    router: router::Peer<Events, T, B>,
    timers: Timers,
    rx: AtomicU64,
    tx: AtomicU64,
}

pub struct Timers {}

pub struct Events();

impl router::Callbacks for Events {
    type Opaque = Timers;

    fn send(t: &Timers, size: usize, data: bool, sent: bool) {}

    fn recv(t: &Timers, size: usize, data: bool, sent: bool) {}

    fn need_key(t: &Timers) {}
}

struct Handshake {
    device: handshake::Device,
    active: bool,
}

struct WireguardInner<T: Tun, B: Bind> {
    // identify and configuration map
    peers: RwLock<HashMap<[u8; 32], Peer<T, B>>>,

    // cryptkey routing
    router: router::Device<Events, T, B>,

    // handshake related state
    handshake: RwLock<Handshake>,
    under_load: AtomicBool,
    pending: AtomicUsize, // num of pending handshake packets in queue
    queue: Mutex<Sender<(Vec<u8>, B::Endpoint)>>,

    // IO
    bind: B,
}

pub struct Wireguard<T: Tun, B: Bind> {
    state: Arc<WireguardInner<T, B>>,
}

impl<T: Tun, B: Bind> Wireguard<T, B> {
    fn set_key(&self, sk: Option<StaticSecret>) {
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

    fn new(tun: T, bind: B) -> Wireguard<T, B> {
        // create device state
        let mut rng = OsRng::new().unwrap();
        let (tx, rx): (Sender<(Vec<u8>, B::Endpoint)>, _) = bounded(SIZE_HANDSHAKE_QUEUE);
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
                for (msg, src) in rx {
                    wg.pending.fetch_sub(1, Ordering::SeqCst);

                    // feed message to handshake device
                    let src_validate = (&src).into_address(); // TODO avoid
                    let state = wg.handshake.read();
                    if !state.active {
                        continue;
                    }

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
                                // add keypair to peer and free any unused ids
                                if let Some(keypair) = keypair {
                                    if let Some(peer) = wg.peers.read().get(pk.as_bytes()) {
                                        for id in peer.0.router.add_keypair(keypair) {
                                            state.device.release(id);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => debug!("handshake worker, error = {:?}", e),
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
                    // read UDP packet into vector
                    let size = tun.mtu() + 148; // maximum message size
                    let mut msg: Vec<u8> = Vec::with_capacity(size);
                    msg.resize(size, 0);
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

                            wg.queue.lock().send((msg, src)).unwrap();
                        }
                        router::TYPE_TRANSPORT => {
                            // transport message

                            // pad the message

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
                // read a new IP packet
                let mtu = tun.mtu();
                let size = mtu + 148;
                let mut msg: Vec<u8> = Vec::with_capacity(size + router::CAPACITY_MESSAGE_POSTFIX);
                let size = tun.read(&mut msg[..], router::SIZE_MESSAGE_PREFIX).unwrap();
                msg.truncate(size);

                // pad message to multiple of 16
                while msg.len() < mtu && msg.len() % 16 != 0 {
                    msg.push(0);
                }

                // crypt-key route
                let _ = wg.router.send(msg);
            });
        }

        Wireguard { state: wg }
    }
}
