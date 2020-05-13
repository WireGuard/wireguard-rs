use super::dummy;
use super::wireguard::WireGuard;

use std::convert::TryInto;
use std::net::IpAddr;

use hex;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use x25519_dalek::{PublicKey, StaticSecret};

use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;

pub fn make_packet(size: usize, src: IpAddr, dst: IpAddr, id: u64) -> Vec<u8> {
    // expand pseudo random payload
    let mut rng: _ = ChaCha8Rng::seed_from_u64(id);
    let mut p: Vec<u8> = vec![0; size];
    rng.fill_bytes(&mut p);

    // create "IP packet"
    let mut msg = Vec::with_capacity(size);
    match dst {
        IpAddr::V4(dst) => {
            let length = size + MutableIpv4Packet::minimum_packet_size();
            msg.resize(length, 0);

            let mut packet = MutableIpv4Packet::new(&mut msg[..]).unwrap();
            packet.set_destination(dst);
            packet.set_total_length(length.try_into().expect("length too great for IPv4 packet"));
            packet.set_source(if let IpAddr::V4(src) = src {
                src
            } else {
                panic!("src.version != dst.version")
            });
            packet.set_payload(&p);
            packet.set_version(4);
        }
        IpAddr::V6(dst) => {
            let length = size + MutableIpv6Packet::minimum_packet_size();
            msg.resize(length, 0);

            let mut packet = MutableIpv6Packet::new(&mut msg[..]).unwrap();
            packet.set_destination(dst);
            packet.set_payload_length(size.try_into().expect("length too great for IPv6 packet"));
            packet.set_source(if let IpAddr::V6(src) = src {
                src
            } else {
                panic!("src.version != dst.version")
            });
            packet.set_payload(&p);
            packet.set_version(6);
        }
    }
    msg
}

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

/* Create and configure
 * two matching pure (no side-effects) instances of WireGuard.
 *
 * Test:
 *
 * - Handshaking completes successfully
 * - All packets up to MTU are delivered
 * - All packets are delivered in-order
 */
#[test]
fn test_pure_wireguard() {
    init();

    // create WG instances for dummy TUN devices

    let (fake1, tun_reader1, tun_writer1, _) = dummy::TunTest::create(true);
    let wg1: WireGuard<dummy::TunTest, dummy::PairBind> = WireGuard::new(tun_writer1);
    wg1.add_tun_reader(tun_reader1);
    wg1.up(1500);

    let (fake2, tun_reader2, tun_writer2, _) = dummy::TunTest::create(true);
    let wg2: WireGuard<dummy::TunTest, dummy::PairBind> = WireGuard::new(tun_writer2);
    wg2.add_tun_reader(tun_reader2);
    wg2.up(1500);

    // create pair bind to connect the interfaces "over the internet"

    let ((bind_reader1, bind_writer1), (bind_reader2, bind_writer2)) = dummy::PairBind::pair();

    wg1.set_writer(bind_writer1);
    wg2.set_writer(bind_writer2);

    wg1.add_udp_reader(bind_reader1);
    wg2.add_udp_reader(bind_reader2);

    // configure (public, private) key pairs

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

    // configure crypto-key router

    {
        let peers1 = wg1.peers.read();
        let peers2 = wg2.peers.read();

        let peer2 = peers1.get(&pk2).unwrap();
        let peer1 = peers2.get(&pk1).unwrap();

        peer1.add_allowed_ip("192.168.1.0".parse().unwrap(), 24);

        peer2.add_allowed_ip("192.168.2.0".parse().unwrap(), 24);

        // set endpoint (the other should be learned dynamically)

        peer2.set_endpoint(dummy::UnitEndpoint::new());
    }

    let num_packets = 20;

    // send IP packets (causing a new handshake)

    {
        let mut packets: Vec<Vec<u8>> = Vec::with_capacity(num_packets);

        for id in 0..num_packets {
            packets.push(make_packet(
                50 * id as usize,                // size
                "192.168.1.20".parse().unwrap(), // src
                "192.168.2.10".parse().unwrap(), // dst
                id as u64,                       // prng seed
            ));
        }

        let mut backup = packets.clone();

        while let Some(p) = packets.pop() {
            println!("send");
            fake1.write(p);
        }

        while let Some(p) = backup.pop() {
            println!("read");
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
