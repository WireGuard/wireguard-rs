use crate::handshake;
use crate::router;
use crate::types::{Bind, Tun};

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use byteorder::{ByteOrder, LittleEndian};
use crossbeam_channel::bounded;
use x25519_dalek::StaticSecret;

const SIZE_HANDSHAKE_QUEUE: usize = 128;
const THRESHOLD_UNDER_LOAD: usize = SIZE_HANDSHAKE_QUEUE / 4;
const DURATION_UNDER_LOAD: Duration = Duration::from_millis(10_000);

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

    fn new(tun: T, bind: B) -> Wireguard<T, B> {
        let router = Arc::new(router::Device::new(
            num_cpus::get(),
            tun.clone(),
            bind.clone(),
        ));

        let handshake_staged = Arc::new(AtomicUsize::new(0));

        // start UDP read IO thread
        let (handshake_tx, handshake_rx) = bounded(128);
        {
            let tun = tun.clone();
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
                            if under_load.elapsed() < DURATION_UNDER_LOAD {
                                handshake_tx.send((msg, Some(src))).unwrap();
                            } else {
                                handshake_tx.send((msg, None)).unwrap();
                            }
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
            let handshake_rx = handshake_rx.clone();
            thread::spawn(move || loop {
                let (msg, src) = handshake_rx.recv().unwrap(); // TODO handle error
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
