use super::wireguard::Wireguard;
use super::{bind, dummy, tun};

use std::net::IpAddr;
use std::thread;
use std::time::Duration;

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;

fn make_packet(size: usize, src: IpAddr, dst: IpAddr) -> Vec<u8> {
    // create "IP packet"
    let mut msg = Vec::with_capacity(size);
    msg.resize(size, 0);
    match dst {
        IpAddr::V4(dst) => {
            let mut packet = MutableIpv4Packet::new(&mut msg[..]).unwrap();
            packet.set_destination(dst);
            packet.set_source(if let IpAddr::V4(src) = src {
                src
            } else {
                panic!("src.version != dst.version")
            });
            packet.set_version(4);
        }
        IpAddr::V6(dst) => {
            let mut packet = MutableIpv6Packet::new(&mut msg[..]).unwrap();
            packet.set_destination(dst);
            packet.set_source(if let IpAddr::V6(src) = src {
                src
            } else {
                panic!("src.version != dst.version")
            });
            packet.set_version(6);
        }
    }
    msg
}

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn wait() {
    thread::sleep(Duration::from_millis(500));
}

/* Create and configure two matching pure instances of WireGuard
 *
 */
#[test]
fn test_pure_wireguard() {
    init();

    // create WG instances for fake TUN devices

    let (fake1, tun_reader1, tun_writer1, mtu1) = dummy::TunTest::create(1500, true);
    let wg1: Wireguard<dummy::TunTest, dummy::PairBind> =
        Wireguard::new(vec![tun_reader1], tun_writer1, mtu1);

    let (fake2, tun_reader2, tun_writer2, mtu2) = dummy::TunTest::create(1500, true);
    let wg2: Wireguard<dummy::TunTest, dummy::PairBind> =
        Wireguard::new(vec![tun_reader2], tun_writer2, mtu2);

    // create pair bind to connect the interfaces "over the internet"

    let ((bind_reader1, bind_writer1), (bind_reader2, bind_writer2)) = dummy::PairBind::pair();

    wg1.set_writer(bind_writer1);
    wg2.set_writer(bind_writer2);

    wg1.add_reader(bind_reader1);
    wg2.add_reader(bind_reader2);

    // generate (public, pivate) key pairs

    let mut rng = OsRng::new().unwrap();
    let sk1 = StaticSecret::new(&mut rng);
    let sk2 = StaticSecret::new(&mut rng);
    let pk1 = PublicKey::from(&sk1);
    let pk2 = PublicKey::from(&sk2);

    wg1.new_peer(pk2);
    wg2.new_peer(pk1);

    wg1.set_key(Some(sk1));
    wg2.set_key(Some(sk2));

    // configure cryptkey router

    let peer2 = wg1.lookup_peer(&pk2).unwrap();
    let peer1 = wg2.lookup_peer(&pk1).unwrap();

    peer1.router.add_subnet("192.168.2.0".parse().unwrap(), 24);
    peer2.router.add_subnet("192.168.1.0".parse().unwrap(), 24);

    // set endpoints

    peer1.router.set_endpoint(dummy::UnitEndpoint::new());
    peer2.router.set_endpoint(dummy::UnitEndpoint::new());

    // create IP packets (causing a new handshake)

    let packet_p1_to_p2 = make_packet(
        1000,
        "192.168.2.20".parse().unwrap(), // src
        "192.168.1.10".parse().unwrap(), // dst
    );

    fake1.write(packet_p1_to_p2);
}
