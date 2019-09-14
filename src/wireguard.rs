use crate::handshake;
use crate::router;
use crate::types::{Bind, Tun};

use byteorder::{ByteOrder, LittleEndian};

use std::thread;

use x25519_dalek::StaticSecret;

pub struct Timers {}

pub struct Events();

impl router::Callbacks for Events {
    type Opaque = Timers;

    fn send(t: &Timers, size: usize, data: bool, sent: bool) {}

    fn recv(t: &Timers, size: usize, data: bool, sent: bool) {}

    fn need_key(t: &Timers) {}
}

pub struct Wireguard<T: Tun, B: Bind> {
    router: router::Device<Events, T, B>,
    handshake: Option<handshake::Device<()>>,
}

impl<T: Tun, B: Bind> Wireguard<T, B> {
    fn new(tun: T, bind: B) -> Wireguard<T, B> {
        let router = router::Device::new(num_cpus::get(), tun.clone(), bind.clone());

        // start UDP read IO thread
        {
            let tun = tun.clone();
            thread::spawn(move || {
                loop {
                    // read UDP packet into vector
                    let size = tun.mtu() + 148; // maximum message size
                    let mut msg: Vec<u8> =
                        Vec::with_capacity(size + router::CAPACITY_MESSAGE_POSTFIX);
                    msg.resize(size, 0);
                    let (size, src) = bind.recv(&mut msg).unwrap(); // TODO handle error
                    msg.truncate(size);

                    // message type de-multiplexer
                    if msg.len() < 4 {
                        continue;
                    }
                    match LittleEndian::read_u32(&msg[..]) {
                        handshake::TYPE_COOKIE_REPLY
                        | handshake::TYPE_INITIATION
                        | handshake::TYPE_RESPONSE => {
                            // handshake message
                        }
                        router::TYPE_TRANSPORT => {
                            // transport message
                        }
                        _ => (),
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
