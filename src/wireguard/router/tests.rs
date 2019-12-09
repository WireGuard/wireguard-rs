use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use num_cpus;

use super::super::dummy;
use super::super::dummy_keypair;
use super::super::tests::make_packet;
use super::super::udp::*;
use super::KeyPair;
use super::SIZE_MESSAGE_PREFIX;
use super::{Callbacks, Device};

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
        send: Mutex<Vec<(usize, bool)>>,
        recv: Mutex<Vec<(usize, bool)>>,
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

        fn send(&self) -> Option<(usize, bool)> {
            self.0.send.lock().unwrap().pop()
        }

        fn recv(&self) -> Option<(usize, bool)> {
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

        fn send(t: &Self::Opaque, size: usize, sent: bool, _keypair: &Arc<KeyPair>, _counter: u64) {
            t.0.send.lock().unwrap().push((size, sent))
        }

        fn recv(t: &Self::Opaque, size: usize, sent: bool, _keypair: &Arc<KeyPair>) {
            t.0.recv.lock().unwrap().push((size, sent))
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
        thread::sleep(Duration::from_millis(15));
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn make_packet_padded(size: usize, src: IpAddr, dst: IpAddr, id: u64) -> Vec<u8> {
        let p = make_packet(size, src, dst, id);
        let mut o = vec![0; p.len() + SIZE_MESSAGE_PREFIX];
        o[SIZE_MESSAGE_PREFIX..SIZE_MESSAGE_PREFIX + p.len()].copy_from_slice(&p[..]);
        o
    }

    #[bench]
    fn bench_outbound(b: &mut Bencher) {
        struct BencherCallbacks {}
        impl Callbacks for BencherCallbacks {
            type Opaque = Arc<AtomicUsize>;
            fn send(
                t: &Self::Opaque,
                size: usize,
                _sent: bool,
                _keypair: &Arc<KeyPair>,
                _counter: u64,
            ) {
                t.fetch_add(size, Ordering::SeqCst);
            }
            fn recv(_: &Self::Opaque, _size: usize, _sent: bool, _keypair: &Arc<KeyPair>) {}
            fn need_key(_: &Self::Opaque) {}
            fn key_confirmed(_: &Self::Opaque) {}
        }

        // create device
        let (_fake, _reader, tun_writer, _mtu) = dummy::TunTest::create(false);
        let router: Device<_, BencherCallbacks, dummy::TunWriter, dummy::VoidBind> =
            Device::new(num_cpus::get(), tun_writer);

        // add new peer
        let opaque = Arc::new(AtomicUsize::new(0));
        let peer = router.new_peer(opaque.clone());
        peer.add_keypair(dummy_keypair(true));

        // add subnet to peer
        let (mask, len, dst) = ("192.168.1.0", 24, "192.168.1.20");
        let mask: IpAddr = mask.parse().unwrap();
        peer.add_allowed_ip(mask, len);

        // create "IP packet"
        let dst = dst.parse().unwrap();
        let src = match dst {
            IpAddr::V4(_) => "127.0.0.1".parse().unwrap(),
            IpAddr::V6(_) => "::1".parse().unwrap()
        };
        let msg = make_packet_padded(1024, src, dst, 0);

        // every iteration sends 10 GB
        b.iter(|| {
            opaque.store(0, Ordering::SeqCst);
            while opaque.load(Ordering::Acquire) < 10 * 1024 * 1024 {
                router.send(msg.to_vec()).unwrap();
            }
        });
    }

    #[test]
    fn test_outbound() {
        init();

        // create device
        let (_fake, _reader, tun_writer, _mtu) = dummy::TunTest::create(false);
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

        for (num, (mask, len, dst, okay)) in tests.iter().enumerate() {
            println!("Check: {} {} {}/{}", dst, if *okay { "\\in" } else { "\\notin" }, mask, len);
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
                peer.add_allowed_ip(mask, *len);

                // create "IP packet"
                let dst = dst.parse().unwrap();
                let src = match dst {
                    IpAddr::V4(_) => "127.0.0.1".parse().unwrap(),
                    IpAddr::V6(_) => "::1".parse().unwrap()
                };
                let msg = make_packet_padded(1024, src, dst, 0);

                // cryptkey route the IP packet
                let res = router.send(msg);

                // allow some scheduling
                wait();

                if *okay {
                    // cryptkey routing succeeded
                    assert!(res.is_ok(), "crypt-key routing should succeed: {:?}", res);
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
                            Some((SIZE_KEEPALIVE, false))
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

        println!("Test complete, drop device");
    }

    #[test]
    fn test_bidirectional() {
        init();

        let tests = [
            (
                ("192.168.1.0", 24, "192.168.1.20", true),
                ("172.133.133.133", 32, "172.133.133.133", true),
            ),
            (
                ("192.168.1.0", 24, "192.168.1.20", true),
                ("172.133.133.133", 32, "172.133.133.133", true),
            ),
            (
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

        for stage in vec![true, false] {
            for (p1, p2) in tests.iter() {
                let ((bind_reader1, bind_writer1), (bind_reader2, bind_writer2)) =
                    dummy::PairBind::pair();

                // create matching device
                let (_fake, _, tun_writer1, _) = dummy::TunTest::create(false);
                let (_fake, _, tun_writer2, _) = dummy::TunTest::create(false);

                let router1: Device<_, TestCallbacks, _, _> = Device::new(1, tun_writer1);
                router1.set_outbound_writer(bind_writer1);

                let router2: Device<_, TestCallbacks, _, _> = Device::new(1, tun_writer2);
                router2.set_outbound_writer(bind_writer2);

                // prepare opaque values for tracing callbacks

                let opaque1 = Opaque::new();
                let opaque2 = Opaque::new();

                // create peers with matching keypairs and assign subnets

                let peer1 = router1.new_peer(opaque1.clone());
                let peer2 = router2.new_peer(opaque2.clone());

                {
                    let (mask, len, _ip, _okay) = p1;
                    let mask: IpAddr = mask.parse().unwrap();
                    peer1.add_allowed_ip(mask, *len);
                    peer1.add_keypair(dummy_keypair(false));
                }

                {
                    let (mask, len, _ip, _okay) = p2;
                    let mask: IpAddr = mask.parse().unwrap();
                    peer2.add_allowed_ip(mask, *len);
                    peer2.set_endpoint(dummy::UnitEndpoint::new());
                }

                if stage {
                    println!("confirm using staged packet");

                    // create IP packet
                    let (_mask, _len, ip1, _okay) = p1;
                    let (_mask, _len, ip2, _okay) = p2;
                    let msg = make_packet_padded(
                        1024,
                        ip1.parse().unwrap(), // src
                        ip2.parse().unwrap(), // dst
                        0,
                    );

                    // stage packet for sending
                    router2.send(msg).expect("failed to sent staged packet");
                    wait();

                    // validate events
                    assert!(opaque2.recv().is_none());
                    assert!(
                        opaque2.send().is_none(),
                        "sending should fail as not key is set"
                    );
                    assert!(
                        opaque2.need_key().is_some(),
                        "a new key should be requested since a packet was attempted transmitted"
                    );
                    assert!(opaque2.is_empty(), "callbacks should only run once");
                }

                // this should cause a key-confirmation packet (keepalive or staged packet)
                // this also causes peer1 to learn the "endpoint" for peer2
                assert!(peer1.get_endpoint().is_none());
                peer2.add_keypair(dummy_keypair(true));

                wait();
                assert!(opaque2.send().is_some());
                assert!(opaque2.is_empty(), "events on peer2 should be 'send'");
                assert!(opaque1.is_empty(), "nothing should happened on peer1");

                // read confirming message received by the other end ("across the internet")
                let mut buf = vec![0u8; 2048];
                let (len, from) = bind_reader1.read(&mut buf).unwrap();
                buf.truncate(len);
                router1.recv(from, buf).unwrap();

                wait();
                assert!(opaque1.recv().is_some());
                assert!(opaque1.key_confirmed().is_some());
                assert!(
                    opaque1.is_empty(),
                    "events on peer1 should be 'recv' and 'key_confirmed'"
                );
                assert!(peer1.get_endpoint().is_some());
                assert!(opaque2.is_empty(), "nothing should happened on peer2");

                // now that peer1 has an endpoint
                // route packets : peer1 -> peer2

                for id in 1..11 {
                    println!("round: {}", id);
                    assert!(
                        opaque1.is_empty(),
                        "we should have asserted a value for every callback on peer1"
                    );
                    assert!(
                        opaque2.is_empty(),
                        "we should have asserted a value for every callback on peer2"
                    );

                    // pass IP packet to router
                    let (_mask, _len, ip1, _okay) = p1;
                    let (_mask, _len, ip2, _okay) = p2;
                    let msg =
                        make_packet_padded(
                            1024, 
                            ip2.parse().unwrap(), // src
                            ip1.parse().unwrap(), // dst
                            id
                        );
                    router1.send(msg).unwrap();

                    wait();
                    assert!(opaque1.send().is_some(), "encryption should succeed");
                    assert!(
                        opaque1.recv().is_none(),
                        "receiving callback should not be called"
                    );
                    assert!(opaque1.need_key().is_none());

                    // receive ("across the internet") on the other end
                    let mut buf = vec![0u8; 2048];
                    let (len, from) = bind_reader2.read(&mut buf).unwrap();
                    buf.truncate(len);
                    router2.recv(from, buf).unwrap();

                    wait();
                    assert!(
                        opaque2.send().is_none(),
                        "sending callback should not be called"
                    );
                    assert!(
                        opaque2.recv().is_some(),
                        "decryption and routing should succeed"
                    );
                    assert!(opaque2.need_key().is_none());
                }
            }
        }
    }
}
