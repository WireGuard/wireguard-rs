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

use super::super::types::{Bind, Endpoint, Key, KeyPair, Tun};
use super::{Callbacks, Device, SIZE_MESSAGE_PREFIX};

extern crate test;

const SIZE_KEEPALIVE: usize = 32;

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

#[derive(Clone, Copy)]
struct UnitEndpoint {}

impl Endpoint for UnitEndpoint {
    fn from_address(_: SocketAddr) -> UnitEndpoint {
        UnitEndpoint {}
    }
    fn into_address(&self) -> SocketAddr {
        "127.0.0.1:8080".parse().unwrap()
    }
}

#[derive(Clone, Copy)]
struct TunTest {}

impl Tun for TunTest {
    type Error = TunError;

    fn mtu(&self) -> usize {
        1500
    }

    fn read(&self, _buf: &mut [u8], _offset: usize) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn write(&self, _src: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

/* Bind implemenentations */

#[derive(Clone, Copy)]
struct VoidBind {}

impl Bind for VoidBind {
    type Error = BindError;
    type Endpoint = UnitEndpoint;

    fn new() -> VoidBind {
        VoidBind {}
    }

    fn set_port(&self, _port: u16) -> Result<(), Self::Error> {
        Ok(())
    }

    fn get_port(&self) -> Option<u16> {
        None
    }

    fn recv(&self, _buf: &mut [u8]) -> Result<(usize, Self::Endpoint), Self::Error> {
        Ok((0, UnitEndpoint {}))
    }

    fn send(&self, _buf: &[u8], _dst: &Self::Endpoint) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Clone)]
struct PairBind {
    send: Arc<Mutex<SyncSender<Vec<u8>>>>,
    recv: Arc<Mutex<Receiver<Vec<u8>>>>,
}

impl Bind for PairBind {
    type Error = BindError;
    type Endpoint = UnitEndpoint;

    fn new() -> PairBind {
        PairBind {
            send: Arc::new(Mutex::new(sync_channel(0).0)),
            recv: Arc::new(Mutex::new(sync_channel(0).1)),
        }
    }

    fn set_port(&self, _port: u16) -> Result<(), Self::Error> {
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
        let len = vec.len();
        buf[..len].copy_from_slice(&vec[..]);
        Ok((vec.len(), UnitEndpoint {}))
    }

    fn send(&self, buf: &[u8], _dst: &Self::Endpoint) -> Result<(), Self::Error> {
        let owned = buf.to_owned();
        match self.send.lock().unwrap().send(owned) {
            Err(_) => Err(BindError::Disconnected),
            Ok(_) => Ok(()),
        }
    }
}

fn bind_pair() -> (PairBind, PairBind) {
    let (tx1, rx1) = sync_channel(128);
    let (tx2, rx2) = sync_channel(128);
    (
        PairBind {
            send: Arc::new(Mutex::new(tx1)),
            recv: Arc::new(Mutex::new(rx2)),
        },
        PairBind {
            send: Arc::new(Mutex::new(tx2)),
            recv: Arc::new(Mutex::new(rx1)),
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
    use std::sync::atomic::AtomicUsize;
    use test::Bencher;

    // type for tracking events inside the router module
    struct Flags {
        send: Mutex<Vec<(usize, bool, bool)>>,
        recv: Mutex<Vec<(usize, bool, bool)>>,
        need_key: Mutex<Vec<()>>,
    }

    #[derive(Clone)]
    struct Opaque(Arc<Flags>);

    struct TestCallbacks();

    impl Opaque {
        fn new() -> Opaque {
            Opaque(Arc::new(Flags {
                send: Mutex::new(vec![]),
                recv: Mutex::new(vec![]),
                need_key: Mutex::new(vec![]),
            }))
        }

        fn reset(&self) {
            self.0.send.lock().unwrap().clear();
            self.0.recv.lock().unwrap().clear();
            self.0.need_key.lock().unwrap().clear();
        }

        fn send(&self) -> Option<(usize, bool, bool)> {
            self.0.send.lock().unwrap().pop()
        }

        fn recv(&self) -> Option<(usize, bool, bool)> {
            self.0.recv.lock().unwrap().pop()
        }

        fn need_key(&self) -> Option<()> {
            self.0.need_key.lock().unwrap().pop()
        }

        fn is_empty(&self) -> bool {
            let send = self.0.send.lock().unwrap();
            let recv = self.0.recv.lock().unwrap();
            let need_key = self.0.need_key.lock().unwrap();
            send.is_empty() && recv.is_empty() && need_key.is_empty()
        }
    }

    impl Callbacks for TestCallbacks {
        type Opaque = Opaque;

        fn send(t: &Self::Opaque, size: usize, data: bool, sent: bool) {
            t.0.send.lock().unwrap().push((size, data, sent))
        }

        fn recv(t: &Self::Opaque, size: usize, data: bool, sent: bool) {
            t.0.recv.lock().unwrap().push((size, data, sent))
        }

        fn need_key(t: &Self::Opaque) {
            t.0.need_key.lock().unwrap().push(());
        }
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
        struct BencherCallbacks {}
        impl Callbacks for BencherCallbacks {
            type Opaque = Arc<AtomicUsize>;
            fn send(t: &Self::Opaque, size: usize, _data: bool, _sent: bool) {
                t.fetch_add(size, Ordering::SeqCst);
            }
            fn recv(_: &Self::Opaque, _size: usize, _data: bool, _sent: bool) {}
            fn need_key(_: &Self::Opaque) {}
        }

        // create device
        let router: Device<BencherCallbacks, TunTest, VoidBind> =
            Device::new(num_cpus::get(), TunTest {}, VoidBind::new());

        // add new peer
        let opaque = Arc::new(AtomicUsize::new(0));
        let peer = router.new_peer(opaque.clone());
        peer.add_keypair(dummy_keypair(true));

        // add subnet to peer
        let (mask, len, ip) = ("192.168.1.0", 24, "192.168.1.20");
        let mask: IpAddr = mask.parse().unwrap();
        let ip1: IpAddr = ip.parse().unwrap();
        peer.add_subnet(mask, len);

        // every iteration sends 50 GB
        b.iter(|| {
            opaque.store(0, Ordering::SeqCst);
            let msg = make_packet(1024, ip1);
            while opaque.load(Ordering::Acquire) < 10 * 1024 * 1024 {
                router.send(msg.to_vec()).unwrap();
            }
        });
    }

    #[test]
    fn test_outbound() {
        init();

        // create device
        let router: Device<TestCallbacks, _, _> = Device::new(1, TunTest {}, VoidBind::new());

        let tests = vec![
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
        ];

        for (num, (mask, len, ip, okay)) in tests.iter().enumerate() {
            for set_key in vec![true, false] {
                debug!("index = {}, set_key = {}", num, set_key);

                // add new peer
                let opaque = Opaque::new();
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
                        opaque.need_key().is_some(),
                        !set_key,
                        "should have requested a new key, if no encryption state was set"
                    );
                    assert_eq!(
                        opaque.send().is_some(),
                        set_key,
                        "transmission should have been attempted"
                    );
                    assert!(
                        opaque.recv().is_none(),
                        "no messages should have been marked as received"
                    );
                } else {
                    // no such cryptkey route
                    assert!(res.is_err(), "crypt-key routing should fail");
                    assert!(
                        opaque.need_key().is_none(),
                        "should not request a new-key if crypt-key routing failed"
                    );
                    assert_eq!(
                        opaque.send(),
                        if set_key {
                            Some((SIZE_KEEPALIVE, false, false))
                        } else {
                            None
                        },
                        "transmission should only happen if key was set (keepalive)",
                    );
                    assert!(
                        opaque.recv().is_none(),
                        "no messages should have been marked as received",
                    );
                }
            }
        }
    }

    fn wait() {
        thread::sleep(Duration::from_millis(20));
    }

    #[test]
    fn test_outbound_inbound() {
        init();

        let tests = [
            (
                false, // confirm with keepalive
                ("192.168.1.0", 24, "192.168.1.20", true),
                ("172.133.133.133", 32, "172.133.133.133", true),
            ),
            (
                true, // confirm with staged packet
                ("192.168.1.0", 24, "192.168.1.20", true),
                ("172.133.133.133", 32, "172.133.133.133", true),
            ),
        ];

        for (stage, p1, p2) in tests.iter() {
            let (bind1, bind2) = bind_pair();

            // create matching devices

            let router1: Device<TestCallbacks, _, _> = Device::new(1, TunTest {}, bind1.clone());

            let router2: Device<TestCallbacks, _, _> = Device::new(1, TunTest {}, bind2.clone());

            // prepare opaque values for tracing callbacks

            let opaq1 = Opaque::new();
            let opaq2 = Opaque::new();

            // create peers with matching keypairs and assign subnets

            let (mask, len, _ip, _okay) = p1;
            let peer1 = router1.new_peer(opaq1.clone());
            let mask: IpAddr = mask.parse().unwrap();
            peer1.add_subnet(mask, *len);
            peer1.add_keypair(dummy_keypair(false));

            let (mask, len, _ip, _okay) = p2;
            let peer2 = router2.new_peer(opaq2.clone());
            let mask: IpAddr = mask.parse().unwrap();
            peer2.add_subnet(mask, *len);
            peer2.set_endpoint("127.0.0.1:8080".parse().unwrap());

            if *stage {
                // stage a packet which can be used for confirmation (in place of a keepalive)
                let (_mask, _len, ip, _okay) = p2;
                let msg = make_packet(1024, ip.parse().unwrap());
                router2.send(msg).expect("failed to sent staged packet");

                wait();
                assert!(opaq2.recv().is_none());
                assert!(
                    opaq2.send().is_none(),
                    "sending should fail as not key is set"
                );
                assert!(
                    opaq2.need_key().is_some(),
                    "a new key should be requested since a packet was attempted transmitted"
                );
                assert!(opaq2.is_empty(), "callbacks should only run once");
            }

            // this should cause a key-confirmation packet (keepalive or staged packet)
            // this also causes peer1 to learn the "endpoint" for peer2
            assert!(peer1.get_endpoint().is_none());
            peer2.add_keypair(dummy_keypair(true));

            wait();
            assert!(opaq2.send().is_some());
            assert!(opaq2.recv().is_none());
            assert!(opaq2.need_key().is_none());
            assert!(opaq2.is_empty());
            assert!(opaq1.is_empty(), "nothing should happened on peer1");

            // read confirming message received by the other end ("across the internet")
            let mut buf = vec![0u8; 2048];
            let (len, from) = bind1.recv(&mut buf).unwrap();
            buf.truncate(len);
            router1.recv(from, buf).unwrap();

            wait();
            assert!(opaq1.send().is_none());
            assert!(opaq1.recv().is_some());
            assert!(opaq1.need_key().is_none());
            assert!(opaq1.is_empty());
            assert!(peer1.get_endpoint().is_some());
            assert!(opaq2.is_empty(), "nothing should happened on peer2");

            // how that peer1 has an endpoint
            // route packets : peer1 -> peer2

            for _ in 0..10 {
                assert!(
                    opaq1.is_empty(),
                    "we should have asserted a value for every callback on peer1"
                );
                assert!(
                    opaq2.is_empty(),
                    "we should have asserted a value for every callback on peer2"
                );

                // pass IP packet to router
                let (_mask, _len, ip, _okay) = p1;
                let msg = make_packet(1024, ip.parse().unwrap());
                router1.send(msg).unwrap();

                wait();
                assert!(opaq1.send().is_some());
                assert!(opaq1.recv().is_none());
                assert!(opaq1.need_key().is_none());

                // receive ("across the internet") on the other end
                let mut buf = vec![0u8; 2048];
                let (len, from) = bind2.recv(&mut buf).unwrap();
                buf.truncate(len);
                router2.recv(from, buf).unwrap();

                wait();
                assert!(opaq2.send().is_none());
                assert!(opaq2.recv().is_some());
                assert!(opaq2.need_key().is_none());
            }

            // route packets : peer2 -> peer1
        }
    }
}
