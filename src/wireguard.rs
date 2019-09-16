use crate::handshake;
use crate::router;
use crate::types::{Bind, Endpoint, Tun};

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use log::debug;
use rand::rngs::OsRng;

use byteorder::{ByteOrder, LittleEndian};
use crossbeam_channel::bounded;
use x25519_dalek::StaticSecret;

const SIZE_HANDSHAKE_QUEUE: usize = 128;
const THRESHOLD_UNDER_LOAD: usize = SIZE_HANDSHAKE_QUEUE / 4;
const DURATION_UNDER_LOAD: Duration = Duration::from_millis(10_000);

#[derive(Clone)]
pub struct Peer<T: Tun, B: Bind>(Arc<PeerInner<T, B>>);

pub struct PeerInner<T: Tun, B: Bind> {
    peer: router::Peer<Events, T, B>,
    timers: Timers,
}

pub struct Timers {}

pub struct Events();

impl router::Callbacks for Events {
    type Opaque = Timers;

    fn send(t: &Timers, size: usize, data: bool, sent: bool) {}

    fn recv(t: &Timers, size: usize, data: bool, sent: bool) {}

    fn need_key(t: &Timers) {}
}

pub struct Wireguard<T: Tun, B: Bind> {
    router: Arc<router::Device<Events, T, B>>,
    handshake: Option<Arc<handshake::Device<()>>>,
}

impl<T: Tun, B: Bind> Wireguard<T, B> {
    fn start(&self) {}

    fn new(tun: T, bind: B, sk: StaticSecret) -> Wireguard<T, B> {
        let router = Arc::new(router::Device::new(
            num_cpus::get(),
            tun.clone(),
            bind.clone(),
        ));

        let handshake_staged = Arc::new(AtomicUsize::new(0));
        let handshake_device: Arc<handshake::Device<Peer<T, B>>> =
            Arc::new(handshake::Device::new(sk));

        // start UDP read IO thread
        let (handshake_tx, handshake_rx) = bounded(128);
        {
            let tun = tun.clone();
            let bind = bind.clone();
            thread::spawn(move || {
                let mut under_load =
                    Instant::now() - DURATION_UNDER_LOAD - Duration::from_millis(1000);

                loop {
                    // read UDP packet into vector
                    let size = tun.mtu() + 148; // maximum message size
                    let mut msg: Vec<u8> =
                        Vec::with_capacity(size + router::CAPACITY_MESSAGE_POSTFIX);
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
                            // detect if under load
                            if handshake_staged.fetch_add(1, Ordering::SeqCst)
                                > THRESHOLD_UNDER_LOAD
                            {
                                under_load = Instant::now()
                            }

                            // pass source address along if under load
                            handshake_tx
                                .send((msg, src, under_load.elapsed() < DURATION_UNDER_LOAD))
                                .unwrap();
                        }
                        router::TYPE_TRANSPORT => {
                            // transport message
                        }
                        _ => (),
                    }
                }
            });
        }

        // start handshake workers
        for _ in 0..num_cpus::get() {
            let bind = bind.clone();
            let handshake_rx = handshake_rx.clone();
            let handshake_device = handshake_device.clone();
            thread::spawn(move || {
                // prepare OsRng instance for this thread
                let mut rng = OsRng::new().unwrap();

                // process elements from the handshake queue
                for (msg, src, under_load) in handshake_rx {
                    // feed message to handshake device
                    let src_validate = (&src).into_address(); // TODO avoid
                    match handshake_device.process(
                        &mut rng,
                        &msg[..],
                        if under_load {
                            Some(&src_validate)
                        } else {
                            None
                        },
                    ) {
                        Ok((identity, msg, keypair)) => {
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
                            if let Some(identity) = identity {
                                // add keypair to peer and free any unused ids
                                if let Some(keypair) = keypair {
                                    for id in identity.0.peer.add_keypair(keypair) {
                                        handshake_device.release(id);
                                    }
                                }
                            }
                        }
                        Err(e) => debug!("handshake worker, error = {:?}", e),
                    }
                }
            });
        }

        // start TUN read IO thread

        thread::spawn(move || {});

        Wireguard {
            router,
            handshake: None,
        }
    }
}
