#[cfg(feature = "unstable")]
extern crate test;

use super::*;

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

// only used in benchmark
#[cfg(feature = "unstable")]
use std::net::IpAddr;

// only used in benchmark
#[cfg(feature = "unstable")]
use num_cpus;

#[cfg(feature = "unstable")]
use test::Bencher;

//
struct TransmissionCounter {
    sent: AtomicUsize,
    recv: AtomicUsize,
}

impl TransmissionCounter {
    #[allow(dead_code)]
    fn new() -> TransmissionCounter {
        TransmissionCounter {
            sent: AtomicUsize::new(0),
            recv: AtomicUsize::new(0),
        }
    }

    #[allow(dead_code)]
    fn reset(&self) {
        self.sent.store(0, Ordering::SeqCst);
        self.recv.store(0, Ordering::SeqCst);
    }

    #[allow(dead_code)]
    fn sent(&self) -> usize {
        self.sent.load(Ordering::Acquire)
    }

    #[allow(dead_code)]
    fn recv(&self) -> usize {
        self.recv.load(Ordering::Acquire)
    }
}

struct BencherCallbacks {}

impl Callbacks for BencherCallbacks {
    type Opaque = Arc<TransmissionCounter>;
    fn send(t: &Self::Opaque, size: usize, _sent: bool, _keypair: &Arc<KeyPair>, _counter: u64) {
        t.sent.fetch_add(size, Ordering::SeqCst);
    }
    fn recv(t: &Self::Opaque, size: usize, _sent: bool, _keypair: &Arc<KeyPair>) {
        t.recv.fetch_add(size, Ordering::SeqCst);
    }
    fn need_key(_t: &Self::Opaque) {}
    fn key_confirmed(_t: &Self::Opaque) {}
}

#[cfg(feature = "profiler")]
use cpuprofiler::PROFILER;

#[cfg(feature = "profiler")]
fn profiler_stop() {
    println!("Stopping profiler");
    PROFILER.lock().unwrap().stop().unwrap();
}

#[cfg(feature = "profiler")]
fn profiler_start(name: &str) {
    use std::path::Path;

    // find first available path to save profiler output
    let mut n = 0;
    loop {
        let path = format!("./{}-{}.profile", name, n);
        if !Path::new(path.as_str()).exists() {
            println!("Starting profiler: {}", path);
            PROFILER.lock().unwrap().start(path).unwrap();
            break;
        };
        n += 1;
    }
}

#[cfg(feature = "unstable")]
#[bench]
fn bench_router_outbound(b: &mut Bencher) {
    // 10 GB transmission per iteration
    const BYTES_PER_ITER: usize = 100 * 1024 * 1024 * 1024;

    // inner payload of IPv4 packet is 1440 bytes
    const BYTES_PER_PACKET: usize = 1440;

    // create device
    let (_fake, _reader, tun_writer, _mtu) = dummy::TunTest::create(false);
    let router: Device<_, BencherCallbacks, dummy::TunWriter, dummy::VoidBind> =
        Device::new(num_cpus::get_physical(), tun_writer);

    // add peer to router
    let opaque = Arc::new(TransmissionCounter::new());
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
        IpAddr::V6(_) => "::1".parse().unwrap(),
    };
    let packet = make_packet(BYTES_PER_PACKET, src, dst, 0);

    // suffix with zero and reserve capacity for tag
    // (normally done to enable in-place transport message construction)
    let mut msg = pad(&packet);
    msg.reserve(16);

    // setup profiler
    #[cfg(feature = "profiler")]
    profiler_start("outbound");

    // repeatedly transmit 10 GB
    b.iter(|| {
        opaque.reset();
        while opaque.sent() < BYTES_PER_ITER / packet.len() {
            router
                .send(msg.to_vec())
                .expect("failed to crypto-route packet");
        }
    });

    // stop profiler
    #[cfg(feature = "profiler")]
    profiler_stop();
}

/*
#[test]
fn bench_router_bidirectional(b: &mut Bencher) {
    const MAX_SIZE_BODY: usize = 1500;

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

    let p1 = ("192.168.1.0", 24, "192.168.1.20");
    let p2 = ("172.133.133.133", 32, "172.133.133.133");

    let ((bind_reader1, bind_writer1), (bind_reader2, bind_writer2)) = dummy::PairBind::pair();

    let mut confirm_packet_size = SIZE_KEEPALIVE;

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

    if confirm_with_staged_packet {
        // create IP packet
        let (_mask, _len, ip1, _okay) = p1;
        let (_mask, _len, ip2, _okay) = p2;

        let msg = make_packet(
            SIZE_MSG,
            ip1.parse().unwrap(), // src
            ip2.parse().unwrap(), // dst
            0,
        );

        // calculate size of encapsulated IP packet
        confirm_packet_size = msg.len() + SIZE_KEEPALIVE;

        // stage packet for sending
        router2
            .send(pad(&msg))
            .expect("failed to sent staged packet");

        // a new key should have been requested from the handshake machine
        assert_eq!(
            opaque2.need_key.wait(TIMEOUT),
            Some(()),
            "a new key should be requested since a packet was attempted transmitted"
        );

        // no other events should fire
        no_events!(opaque1);
        no_events!(opaque2);
    }

    // add a keypair
    assert_eq!(peer1.get_endpoint(), None, "no endpoint has yet been set");
    peer2.add_keypair(dummy_keypair(true));

    // this should cause a key-confirmation packet (keepalive or staged packet)
    assert_eq!(
        opaque2.send.wait(TIMEOUT),
        Some((confirm_packet_size, true)),
        "expected successful transmission of a confirmation packet"
    );

    // no other events should fire
    no_events!(opaque1);
    no_events!(opaque2);

    // read confirming message received by the other end ("across the internet")
    let mut buf = vec![0u8; SIZE_MSG * 2];
    let (len, from) = bind_reader1.read(&mut buf).unwrap();
    buf.truncate(len);

    assert_eq!(
        len, confirm_packet_size,
        "unexpected size of confirmation message"
    );

    // pass to the router for processing
    router1
        .recv(from, buf)
        .expect("failed to receive confirmation message");

    // check that a receive event is fired
    assert_eq!(
        opaque1.recv.wait(TIMEOUT),
        Some((confirm_packet_size, true)),
        "we expect processing to be successful"
    );

    // the key is confirmed
    assert_eq!(
        opaque1.key_confirmed.wait(TIMEOUT),
        Some(()),
        "confirmation message should confirm the key"
    );

    // peer1 learns the endpoint
    assert!(
        peer1.get_endpoint().is_some(),
        "peer1 should learn the endpoint of peer2 from the confirmation message (roaming)"
    );

    // no other events should fire
    no_events!(opaque1);
    no_events!(opaque2);

    // now that peer1 has an endpoint
    // route packets in the other direction: peer1 -> peer2
    let mut sizes = vec![0, 1, 1500, MAX_SIZE_BODY];
    for _ in 0..100 {
        let body_size: usize = rng.gen();
        let body_size = body_size % MAX_SIZE_BODY;
        sizes.push(body_size);
    }
    for (id, body_size) in sizes.iter().enumerate() {
        println!("packet: id = {}, body_size = {}", id, body_size);

        // pass IP packet to router
        let (_mask, _len, ip1, _okay) = p1;
        let (_mask, _len, ip2, _okay) = p2;
        let msg = make_packet(
            *body_size,
            ip2.parse().unwrap(), // src
            ip1.parse().unwrap(), // dst
            id as u64,
        );

        // calculate encrypted size
        let encrypted_size = msg.len() + SIZE_KEEPALIVE;

        router1
            .send(pad(&msg))
            .expect("we expect routing to be successful");

        // encryption succeeds and the correct size is logged
        assert_eq!(
            opaque1.send.wait(TIMEOUT),
            Some((encrypted_size, true)),
            "expected send event for peer1 -> peer2 payload"
        );

        // otherwise no events
        no_events!(opaque1);
        no_events!(opaque2);

        // receive ("across the internet") on the other end
        let mut buf = vec![0u8; MAX_SIZE_BODY + 512];
        let (len, from) = bind_reader2.read(&mut buf).unwrap();
        buf.truncate(len);
        router2.recv(from, buf).unwrap();

        // check that decryption succeeds
        assert_eq!(
            opaque2.recv.wait(TIMEOUT),
            Some((msg.len() + SIZE_KEEPALIVE, true)),
            "decryption and routing should succeed"
        );

        // otherwise no events
        no_events!(opaque1);
        no_events!(opaque2);
    }
}

#[bench]
fn bench_router_inbound(b: &mut Bencher) {
    struct BencherCallbacks {}
    impl Callbacks for BencherCallbacks {
        type Opaque = Arc<AtomicUsize>;
        fn send(
            _t: &Self::Opaque,
            _size: usize,
            _sent: bool,
            _keypair: &Arc<KeyPair>,
            _counter: u64,
        ) {
        }
        fn recv(t: &Self::Opaque, size: usize, _sent: bool, _keypair: &Arc<KeyPair>) {
            t.fetch_add(size, Ordering::SeqCst);
        }
        fn need_key(_t: &Self::Opaque) {}
        fn key_confirmed(_t: &Self::Opaque) {}
    }

    // create device
    let (_fake, _reader, tun_writer, _mtu) = dummy::TunTest::create(false);
    let router: Device<_, BencherCallbacks, dummy::TunWriter, dummy::VoidBind> =
        Device::new(num_cpus::get_physical(), tun_writer);

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
        IpAddr::V6(_) => "::1".parse().unwrap(),
    };
    let mut msg = pad(&make_packet(1024, src, dst, 0));

    msg.reserve(16);

    #[cfg(feature = "profiler")]
    profiler_start("outbound");

    // every iteration sends 10 GB
    b.iter(|| {
        opaque.store(0, Ordering::SeqCst);
        while opaque.load(Ordering::Acquire) < 10 * 1024 * 1024 {
            router.send(msg.to_vec()).unwrap();
        }
    });

    #[cfg(feature = "profiler")]
    profiler_stop();
}
*/
