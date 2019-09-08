use std::error::Error;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use num_cpus;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;

use super::super::types::{Bind, Key, KeyPair, Tun};
use super::{Device, SIZE_MESSAGE_PREFIX};

extern crate test;

/* Error implementation */

#[derive(Debug)]
enum BindError {
    Disconnected,
}

impl Error for BindError {
    fn description(&self) -> &str {
        "Generic Bind Error"
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindError::Disconnected => write!(f, "PairBind disconnected"),
        }
    }
}

/* TUN implementation */

#[derive(Debug)]
enum TunError {}

impl Error for TunError {
    fn description(&self) -> &str {
        "Generic Tun Error"
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for TunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Not Possible")
    }
}

/* Endpoint implementation */

struct UnitEndpoint {}

impl From<SocketAddr> for UnitEndpoint {
    fn from(addr: SocketAddr) -> UnitEndpoint {
        UnitEndpoint {}
    }
}

impl Into<SocketAddr> for UnitEndpoint {
    fn into(self) -> SocketAddr {
        "127.0.0.1:8080".parse().unwrap()
    }
}

struct TunTest {}

impl Tun for TunTest {
    type Error = TunError;

    fn mtu(&self) -> usize {
        1500
    }

    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn write(&self, src: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

/* Bind implemenentations */

struct VoidBind {}

impl Bind for VoidBind {
    type Error = BindError;
    type Endpoint = UnitEndpoint;

    fn new() -> VoidBind {
        VoidBind {}
    }

    fn set_port(&self, port: u16) -> Result<(), Self::Error> {
        Ok(())
    }

    fn get_port(&self) -> Option<u16> {
        None
    }

    fn recv(&self, buf: &mut [u8]) -> Result<(usize, Self::Endpoint), Self::Error> {
        Ok((0, UnitEndpoint {}))
    }

    fn send(&self, buf: &[u8], dst: &Self::Endpoint) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct PairBind {
    send: Mutex<SyncSender<Vec<u8>>>,
    recv: Mutex<Receiver<Vec<u8>>>,
}

impl Bind for PairBind {
    type Error = BindError;
    type Endpoint = UnitEndpoint;

    fn new() -> PairBind {
        PairBind {
            send: Mutex::new(sync_channel(0).0),
            recv: Mutex::new(sync_channel(0).1),
        }
    }

    fn set_port(&self, port: u16) -> Result<(), Self::Error> {
        Ok(())
    }

    fn get_port(&self) -> Option<u16> {
        None
    }

    fn recv(&self, buf: &mut [u8]) -> Result<(usize, Self::Endpoint), Self::Error> {
        let vec = self
            .recv
            .lock()
            .unwrap()
            .recv()
            .map_err(|_| BindError::Disconnected)?;
        buf.copy_from_slice(&vec[..]);
        Ok((vec.len(), UnitEndpoint {}))
    }

    fn send(&self, buf: &[u8], dst: &Self::Endpoint) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn bind_pair() -> (PairBind, PairBind) {
    let (tx1, rx1) = sync_channel(0);
    let (tx2, rx2) = sync_channel(0);
    (
        PairBind {
            send: Mutex::new(tx1),
            recv: Mutex::new(rx2),
        },
        PairBind {
            send: Mutex::new(tx2),
            recv: Mutex::new(rx1),
        },
    )
}

fn dummy_keypair(initiator: bool) -> KeyPair {
    let k1 = Key {
        key: [0x53u8; 32],
        id: 0x646e6573,
    };
    let k2 = Key {
        key: [0x52u8; 32],
        id: 0x76636572,
    };
    if initiator {
        KeyPair {
            birth: Instant::now(),
            initiator: true,
            send: k1,
            recv: k2,
        }
    } else {
        KeyPair {
            birth: Instant::now(),
            initiator: false,
            send: k2,
            recv: k1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use env_logger;
    use log::debug;
    use std::sync::atomic::AtomicU64;
    use test::Bencher;

    fn get_tests() -> Vec<(&'static str, u32, &'static str, bool)> {
        vec![
            ("192.168.1.0", 24, "192.168.1.20", true),
            ("172.133.133.133", 32, "172.133.133.133", true),
            ("172.133.133.133", 32, "172.133.133.132", false),
            (
                "2001:db8::ff00:42:0000",
                112,
                "2001:db8::ff00:42:3242",
                true,
            ),
            (
                "2001:db8::ff00:42:8000",
                113,
                "2001:db8::ff00:42:0660",
                false,
            ),
            (
                "2001:db8::ff00:42:8000",
                113,
                "2001:db8::ff00:42:ffff",
                true,
            ),
        ]
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn make_packet(size: usize, ip: IpAddr) -> Vec<u8> {
        // create "IP packet"
        let mut msg = Vec::with_capacity(SIZE_MESSAGE_PREFIX + size + 16);
        msg.resize(SIZE_MESSAGE_PREFIX + size, 0);
        match ip {
            IpAddr::V4(ip) => {
                let mut packet = MutableIpv4Packet::new(&mut msg[SIZE_MESSAGE_PREFIX..]).unwrap();
                packet.set_destination(ip);
                packet.set_version(4);
            }
            IpAddr::V6(ip) => {
                let mut packet = MutableIpv6Packet::new(&mut msg[SIZE_MESSAGE_PREFIX..]).unwrap();
                packet.set_destination(ip);
                packet.set_version(6);
            }
        }
        msg
    }

    #[bench]
    fn bench_outbound(b: &mut Bencher) {
        init();

        // type for tracking number of packets
        type Opaque = Arc<AtomicU64>;

        // create device
        let router = Device::new(
            num_cpus::get(),
            TunTest {},
            VoidBind::new(),
            |t: &Opaque, _data: bool, _sent: bool| {
                t.fetch_add(1, Ordering::SeqCst);
            },
            |_t: &Opaque, _data: bool, _sent: bool| {},
            |_t: &Opaque| {},
        );

        // add new peer
        let opaque = Arc::new(AtomicU64::new(0));
        let peer = router.new_peer(opaque.clone());
        peer.add_keypair(dummy_keypair(true));

        // add subnet to peer
        let (mask, len, ip) = ("192.168.1.0", 24, "192.168.1.20");
        let mask: IpAddr = mask.parse().unwrap();
        let ip: IpAddr = ip.parse().unwrap();
        peer.add_subnet(mask, len);

        // every iteration sends 10 MB
        b.iter(|| {
            opaque.store(0, Ordering::SeqCst);
            while opaque.load(Ordering::Acquire) < 10 * 1024 {
                let msg = make_packet(1024, ip);
                router.send(msg).unwrap();
            }
        });
    }

    #[test]
    fn test_outbound() {
        init();

        // type for tracking events inside the router module
        struct Flags {
            send: AtomicBool,
            recv: AtomicBool,
            need_key: AtomicBool,
        }
        type Opaque = Arc<Flags>;

        // create device
        let router = Device::new(
            1,
            TunTest {},
            VoidBind::new(),
            |t: &Opaque, _data: bool, _sent: bool| t.send.store(true, Ordering::SeqCst),
            |t: &Opaque, _data: bool, _sent: bool| t.recv.store(true, Ordering::SeqCst),
            |t: &Opaque| t.need_key.store(true, Ordering::SeqCst),
        );

        let tests = get_tests();
        for (num, (mask, len, ip, okay)) in tests.iter().enumerate() {
            for set_key in vec![true, false] {
                debug!("index = {}, set_key = {}", num, set_key);

                // add new peer
                let opaque = Arc::new(Flags {
                    send: AtomicBool::new(false),
                    recv: AtomicBool::new(false),
                    need_key: AtomicBool::new(false),
                });
                let peer = router.new_peer(opaque.clone());
                let mask: IpAddr = mask.parse().unwrap();

                if set_key {
                    peer.add_keypair(dummy_keypair(true));
                }

                // map subnet to peer
                peer.add_subnet(mask, *len);

                // create "IP packet"
                let msg = make_packet(1024, ip.parse().unwrap());

                // cryptkey route the IP packet
                let res = router.send(msg);

                // allow some scheduling
                thread::sleep(Duration::from_millis(20));

                if *okay {
                    // cryptkey routing succeeded
                    assert!(res.is_ok(), "crypt-key routing should succeed");
                    assert_eq!(
                        opaque.need_key.load(Ordering::Acquire),
                        !set_key,
                        "should have requested a new key, if no encryption state was set"
                    );
                    assert_eq!(
                        opaque.send.load(Ordering::Acquire),
                        set_key,
                        "transmission should have been attempted"
                    );
                    assert_eq!(
                        opaque.recv.load(Ordering::Acquire),
                        false,
                        "no messages should have been marked as received"
                    );
                } else {
                    // no such cryptkey route
                    assert!(res.is_err(), "crypt-key routing should fail");
                    assert_eq!(
                        opaque.need_key.load(Ordering::Acquire),
                        false,
                        "should not request a new-key if crypt-key routing failed"
                    );
                    assert_eq!(
                        opaque.send.load(Ordering::Acquire),
                        false,
                        "transmission should not have been attempted",
                    );
                    assert_eq!(
                        opaque.recv.load(Ordering::Acquire),
                        false,
                        "no messages should have been marked as received",
                    );
                }
            }
        }
    }

    #[test]
    fn test_outbound_inbound() {
        // type for tracking events inside the router module

        struct Flags {
            send: AtomicBool,
            recv: AtomicBool,
            need_key: AtomicBool,
        }
        type Opaque = Arc<Flags>;

        let (bind1, bind2) = bind_pair();

        // create matching devices

        let router1 = Device::new(
            1,
            TunTest {},
            bind1,
            |t: &Opaque, _data: bool, _sent: bool| t.send.store(true, Ordering::SeqCst),
            |t: &Opaque, _data: bool, _sent: bool| t.recv.store(true, Ordering::SeqCst),
            |t: &Opaque| t.need_key.store(true, Ordering::SeqCst),
        );

        let router2 = Device::new(
            1,
            TunTest {},
            bind2,
            |t: &Opaque, _data: bool, _sent: bool| t.send.store(true, Ordering::SeqCst),
            |t: &Opaque, _data: bool, _sent: bool| t.recv.store(true, Ordering::SeqCst),
            |t: &Opaque| t.need_key.store(true, Ordering::SeqCst),
        );

        // create peers with matching keypairs

        let opaq1 = Arc::new(Flags {
            send: AtomicBool::new(false),
            recv: AtomicBool::new(false),
            need_key: AtomicBool::new(false),
        });

        let opaq2 = Arc::new(Flags {
            send: AtomicBool::new(false),
            recv: AtomicBool::new(false),
            need_key: AtomicBool::new(false),
        });

        let peer1 = router1.new_peer(opaq1.clone());
        peer1.set_endpoint("127.0.0.1:8080".parse().unwrap());
        peer1.add_keypair(dummy_keypair(false));

        let peer2 = router2.new_peer(opaq2.clone());
        peer2.set_endpoint("127.0.0.1:8080".parse().unwrap());
        peer2.add_keypair(dummy_keypair(true)); // this should cause an empty key-confirmation packet
    }
}
