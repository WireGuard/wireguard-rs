use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use num_cpus;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;

use super::super::types::bind::*;
use super::super::types::tun::*;
use super::super::types::*;

use super::{Callbacks, Device, SIZE_MESSAGE_PREFIX};

extern crate test;

const SIZE_KEEPALIVE: usize = 32;

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
        key_confirmed: Mutex<Vec<()>>,
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
                key_confirmed: Mutex::new(vec![]),
            }))
        }

        fn reset(&self) {
            self.0.send.lock().unwrap().clear();
            self.0.recv.lock().unwrap().clear();
            self.0.need_key.lock().unwrap().clear();
            self.0.key_confirmed.lock().unwrap().clear();
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

        fn key_confirmed(&self) -> Option<()> {
            self.0.key_confirmed.lock().unwrap().pop()
        }

        // has all events been accounted for by assertions?
        fn is_empty(&self) -> bool {
            let send = self.0.send.lock().unwrap();
            let recv = self.0.recv.lock().unwrap();
            let need_key = self.0.need_key.lock().unwrap();
            let key_confirmed = self.0.key_confirmed.lock().unwrap();
            send.is_empty() && recv.is_empty() && need_key.is_empty() & key_confirmed.is_empty()
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

        fn key_confirmed(t: &Self::Opaque) {
            t.0.key_confirmed.lock().unwrap().push(());
        }
    }

    // wait for scheduling
    fn wait() {
        thread::sleep(Duration::from_millis(50));
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
            fn key_confirmed(_: &Self::Opaque) {}
        }

        // create device
        let (_fake, _reader, tun_writer, _mtu) = dummy::TunTest::create(1500, false);
        let router: Device< _, BencherCallbacks, dummy::TunWriter, dummy::VoidBind> =
            Device::new(num_cpus::get(), tun_writer);

        // add new peer
        let opaque = Arc::new(AtomicUsize::new(0));
        let peer = router.new_peer(opaque.clone());
        peer.add_keypair(dummy::keypair(true));

        // add subnet to peer
        let (mask, len, ip) = ("192.168.1.0", 24, "192.168.1.20");
        let mask: IpAddr = mask.parse().unwrap();
        let ip1: IpAddr = ip.parse().unwrap();
        peer.add_subnet(mask, len);

        // every iteration sends 10 GB
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
        let (_fake, _reader, tun_writer, _mtu) = dummy::TunTest::create(1500, false);
        let router: Device<_, TestCallbacks, _, _> = Device::new(1, tun_writer);
        router.set_outbound_writer(dummy::VoidBind::new());

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
                    peer.add_keypair(dummy::keypair(true));
                }

                // map subnet to peer
                peer.add_subnet(mask, *len);

                // create "IP packet"
                let msg = make_packet(1024, ip.parse().unwrap());

                // cryptkey route the IP packet
                let res = router.send(msg);

                // allow some scheduling
                wait();

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

    #[test]
    fn test_bidirectional() {
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
            (
                false, // confirm with keepalive
                (
                    "2001:db8::ff00:42:8000",
                    113,
                    "2001:db8::ff00:42:ffff",
                    true,
                ),
                (
                    "2001:db8::ff40:42:8000",
                    113,
                    "2001:db8::ff40:42:ffff",
                    true,
                ),
            ),
            (
                false, // confirm with staged packet
                (
                    "2001:db8::ff00:42:8000",
                    113,
                    "2001:db8::ff00:42:ffff",
                    true,
                ),
                (
                    "2001:db8::ff40:42:8000",
                    113,
                    "2001:db8::ff40:42:ffff",
                    true,
                ),
            ),
        ];

        for (stage, p1, p2) in tests.iter() {
            let ((bind_reader1, bind_writer1), (bind_reader2, bind_writer2)) =
                dummy::PairBind::pair();

            // create matching device
            let (_fake, _, tun_writer1, _) = dummy::TunTest::create(1500, false);
            let (_fake, _, tun_writer2, _) = dummy::TunTest::create(1500, false);

            let router1: Device<_, TestCallbacks, _, _> = Device::new(1, tun_writer1);
            router1.set_outbound_writer(bind_writer1);

            let router2: Device<_, TestCallbacks, _, _> = Device::new(1, tun_writer2);
            router2.set_outbound_writer(bind_writer2);

            // prepare opaque values for tracing callbacks

            let opaq1 = Opaque::new();
            let opaq2 = Opaque::new();

            // create peers with matching keypairs and assign subnets

            let (mask, len, _ip, _okay) = p1;
            let peer1 = router1.new_peer(opaq1.clone());
            let mask: IpAddr = mask.parse().unwrap();
            peer1.add_subnet(mask, *len);
            peer1.add_keypair(dummy::keypair(false));

            let (mask, len, _ip, _okay) = p2;
            let peer2 = router2.new_peer(opaq2.clone());
            let mask: IpAddr = mask.parse().unwrap();
            peer2.add_subnet(mask, *len);
            peer2.set_endpoint(dummy::UnitEndpoint::new());

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
            peer2.add_keypair(dummy::keypair(true));

            wait();
            assert!(opaq2.send().is_some());
            assert!(opaq2.is_empty(), "events on peer2 should be 'send'");
            assert!(opaq1.is_empty(), "nothing should happened on peer1");

            // read confirming message received by the other end ("across the internet")
            let mut buf = vec![0u8; 2048];
            let (len, from) = bind_reader1.read(&mut buf).unwrap();
            buf.truncate(len);
            router1.recv(from, buf).unwrap();

            wait();
            assert!(opaq1.recv().is_some());
            assert!(opaq1.key_confirmed().is_some());
            assert!(
                opaq1.is_empty(),
                "events on peer1 should be 'recv' and 'key_confirmed'"
            );
            assert!(peer1.get_endpoint().is_some());
            assert!(opaq2.is_empty(), "nothing should happened on peer2");

            // now that peer1 has an endpoint
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
                let (len, from) = bind_reader2.read(&mut buf).unwrap();
                buf.truncate(len);
                router2.recv(from, buf).unwrap();

                wait();
                assert!(opaq2.send().is_none());
                assert!(opaq2.recv().is_some());
                assert!(opaq2.need_key().is_none());
            }
        }
    }
}
