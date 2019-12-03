use super::dummy;
use super::wireguard::Wireguard;

use std::net::IpAddr;
use std::thread;
use std::time::Duration;

use hex;

use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use x25519_dalek::{PublicKey, StaticSecret};

use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;

pub fn make_packet_src(size: usize, src: IpAddr, id: u64) -> Vec<u8> {
    match src {
        IpAddr::V4(_) => make_packet(size, src, "127.0.0.1".parse().unwrap(), id),
        IpAddr::V6(_) => make_packet(size, src, "::1".parse().unwrap(), id),
    }
}

pub fn make_packet_dst(size: usize, dst: IpAddr, id: u64) -> Vec<u8> {
    match dst {
        IpAddr::V4(_) => make_packet(size, "127.0.0.1".parse().unwrap(), dst, id),
        IpAddr::V6(_) => make_packet(size, "::1".parse().unwrap(), dst, id),
    }
}

pub fn make_packet(size: usize, src: IpAddr, dst: IpAddr, id: u64) -> Vec<u8> {
    // expand pseudo random payload
    let mut rng: _ = ChaCha8Rng::seed_from_u64(id);
    let mut p: Vec<u8> = vec![0; size];
    rng.fill_bytes(&mut p[..]);

    // create "IP packet"
    let mut msg = Vec::with_capacity(size);
    msg.resize(size, 0);
    match dst {
        IpAddr::V4(dst) => {
            let length = size - MutableIpv4Packet::minimum_packet_size();
            let mut packet = MutableIpv4Packet::new(&mut msg[..]).unwrap();
            packet.set_destination(dst);
            packet.set_total_length(size as u16);
            packet.set_source(if let IpAddr::V4(src) = src {
                src
            } else {
                panic!("src.version != dst.version")
            });
            packet.set_payload(&p[..length]);
            packet.set_version(4);
        }
        IpAddr::V6(dst) => {
            let length = size - MutableIpv6Packet::minimum_packet_size();
            let mut packet = MutableIpv6Packet::new(&mut msg[..]).unwrap();
            packet.set_destination(dst);
            packet.set_payload_length(length as u16);
            packet.set_source(if let IpAddr::V6(src) = src {
                src
            } else {
                panic!("src.version != dst.version")
            });
            packet.set_payload(&p[..length]);
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
 */
#[test]
fn test_pure_wireguard() {
    init();

    // create WG instances for dummy TUN devices

    let (fake1, tun_reader1, tun_writer1, _) = dummy::TunTest::create(true);
    let wg1: Wireguard<dummy::TunTest, dummy::PairBind> = Wireguard::new(tun_writer1);
    wg1.add_tun_reader(tun_reader1);
    wg1.up(1500);

    let (fake2, tun_reader2, tun_writer2, _) = dummy::TunTest::create(true);
    let wg2: Wireguard<dummy::TunTest, dummy::PairBind> = Wireguard::new(tun_writer2);
    wg2.add_tun_reader(tun_reader2);
    wg2.up(1500);

    // create pair bind to connect the interfaces "over the internet"

    let ((bind_reader1, bind_writer1), (bind_reader2, bind_writer2)) = dummy::PairBind::pair();

    wg1.set_writer(bind_writer1);
    wg2.set_writer(bind_writer2);

    wg1.add_udp_reader(bind_reader1);
    wg2.add_udp_reader(bind_reader2);

    // generate (public, pivate) key pairs

    let sk1 = StaticSecret::from([
        0x3f, 0x69, 0x86, 0xd1, 0xc0, 0xec, 0x25, 0xa0, 0x9c, 0x8e, 0x56, 0xb5, 0x1d, 0xb7, 0x3c,
        0xed, 0x56, 0x8e, 0x59, 0x9d, 0xd9, 0xc3, 0x98, 0x67, 0x74, 0x69, 0x90, 0xc3, 0x43, 0x36,
        0x78, 0x89,
    ]);

    let sk2 = StaticSecret::from([
        0xfb, 0xd1, 0xd6, 0xe4, 0x65, 0x06, 0xd2, 0xe5, 0xc5, 0xdf, 0x6e, 0xab, 0x51, 0x71, 0xd8,
        0x70, 0xb5, 0xb7, 0x77, 0x51, 0xb4, 0xbe, 0xfb, 0xbc, 0x88, 0x62, 0x40, 0xca, 0x2c, 0xc2,
        0x66, 0xe2,
    ]);

    let pk1 = PublicKey::from(&sk1);

    let pk2 = PublicKey::from(&sk2);

    wg1.add_peer(pk2);
    wg2.add_peer(pk1);

    wg1.set_key(Some(sk1));
    wg2.set_key(Some(sk2));

    // configure cryptkey router

    let peer2 = wg1.lookup_peer(&pk2).unwrap();
    let peer1 = wg2.lookup_peer(&pk1).unwrap();

    peer1
        .router
        .add_allowed_ip("192.168.1.0".parse().unwrap(), 24);

    peer2
        .router
        .add_allowed_ip("192.168.2.0".parse().unwrap(), 24);

    // set endpoint (the other should be learned dynamically)

    peer2.router.set_endpoint(dummy::UnitEndpoint::new());

    let num_packets = 20;

    // send IP packets (causing a new handshake)

    {
        let mut packets: Vec<Vec<u8>> = Vec::with_capacity(num_packets);

        for id in 0..num_packets {
            packets.push(make_packet(
                50 + 50 * id as usize,           // size
                "192.168.1.20".parse().unwrap(), // src
                "192.168.2.10".parse().unwrap(), // dst
                id as u64,                       // prng seed
            ));
        }

        let mut backup = packets.clone();

        while let Some(p) = packets.pop() {
            fake1.write(p);
        }

        while let Some(p) = backup.pop() {
            assert_eq!(
                hex::encode(fake2.read()),
                hex::encode(p),
                "Failed to receive valid IPv4 packet unmodified and in-order"
            );
        }
    }

    // send IP packets (other direction)

    {
        let mut packets: Vec<Vec<u8>> = Vec::with_capacity(num_packets);

        for id in 0..num_packets {
            packets.push(make_packet(
                50 + 50 * id as usize,           // size
                "192.168.2.10".parse().unwrap(), // src
                "192.168.1.20".parse().unwrap(), // dst
                (id + 100) as u64,               // prng seed
            ));
        }

        let mut backup = packets.clone();

        while let Some(p) = packets.pop() {
            fake2.write(p);
        }

        while let Some(p) = backup.pop() {
            assert_eq!(
                hex::encode(fake1.read()),
                hex::encode(p),
                "Failed to receive valid IPv4 packet unmodified and in-order"
            );
        }
    }
}
