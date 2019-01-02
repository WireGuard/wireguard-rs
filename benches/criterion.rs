/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

#![feature(try_from)]

#[macro_use]
extern crate criterion;
extern crate wireguard;
extern crate x25519_dalek;
extern crate rand;
extern crate rips_packets;
extern crate snow;
extern crate socket2;

use criterion::{Benchmark, Criterion, Throughput};
use wireguard::peer::{Peer, Session};
use wireguard::noise;
use wireguard::timestamp::Timestamp;
use x25519_dalek::{generate_secret, generate_public};
use rand::OsRng;
use std::{convert::TryInto, net::SocketAddr, time::Duration};
use rips_packets::ipv4::MutIpv4Packet;
//use std::io::Write;
//use socket2::{Socket, Domain, Type, Protocol};

struct Keypair {
    pub private : [u8; 32],
    pub public  : [u8; 32]
}

impl Keypair {
    pub fn new() -> Keypair {
        let mut rng     = OsRng::new().unwrap();
        let     private = generate_secret(&mut rng);
        let     public  = generate_public(&private).to_bytes();

        Keypair { private, public }

    }
}

fn connected_peers() -> (Peer, [u8; 32], Peer, [u8; 32]) {
    let     init_keys = Keypair::new();
    let     resp_keys = Keypair::new();
    let mut peer_init = Peer::new(Default::default());
    let mut peer_resp = Peer::new(Default::default());
    let mut initiator = noise::build_initiator(&init_keys.private, &resp_keys.public, &None).unwrap();
    let mut responder = noise::build_responder(&resp_keys.private).unwrap();
    let mut buf       = [0u8; 500];

    match responder {
        snow::Session::Handshake(ref mut handshake_state) => {
            handshake_state.set_psk(2, &[0u8; 32]);
        },
        _ => unreachable!()
    }

    let len = initiator.write_message(&[], &mut buf).unwrap();
    let _   = responder.read_message(&buf[..len], &mut []).unwrap();
    let len = responder.write_message(&[], &mut buf).unwrap();
    let _   = initiator.read_message(&buf[..len], &mut []).unwrap();

    let mut init_session = Session::new(initiator.into_transport_mode().unwrap(), 1);
    let mut resp_session = Session::with_their_index(responder.into_transport_mode().unwrap(), 2, init_session.our_index);
    init_session.their_index = resp_session.our_index;
    init_session.birthday = Timestamp::now();
    resp_session.birthday = Timestamp::now();

    peer_init.sessions.current = Some(init_session);
    peer_init.info.endpoint = Some(SocketAddr::from(([127, 0, 0, 1], 443)).into());
    peer_init.info.pub_key = resp_keys.public;

    peer_resp.sessions.current = Some(resp_session);
    peer_resp.info.endpoint = Some(SocketAddr::from(([127, 0, 0, 1], 443)).into());
    peer_resp.info.pub_key = init_keys.public;

    (peer_init, init_keys.private, peer_resp, resp_keys.private)
}

fn benchmarks(c: &mut Criterion) {
    c.bench("handshake", Benchmark::new("initialization", |b| {
        let (mut peer, _, _, _) = connected_peers();
        b.iter(move || {
            peer.initiate_new_session(&[1u8; 32], 1).unwrap()
        });
    }).throughput(Throughput::Elements(1)));

    c.bench("handshake", Benchmark::new("response", |b| {
        let (mut peer_init, init_priv, mut peer_resp, resp_priv) = connected_peers();
        let (_, init, _) = peer_init.initiate_new_session(&init_priv, 1).expect("initiate");
        let init = init.try_into().unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], 443)).into();
        b.iter(move || {
            peer_resp.last_handshake_tai64n = None;
            let handshake = Peer::process_incoming_handshake(&resp_priv, &init).unwrap();
            peer_resp.complete_incoming_handshake(addr, 2, handshake).expect("second half");
        });
    }).throughput(Throughput::Elements(1)));

    c.bench("transport", Benchmark::new("outgoing", |b| {
        let (mut peer_init, _, _, _) = connected_peers();
        b.iter(move || {
            peer_init.handle_outgoing_transport(&[1u8; 1420]).expect("handle_outgoing_transport")
        });
    }).throughput(Throughput::Bytes(1420)));

    c.bench("transport", Benchmark::new("incoming", |b| {
        let (mut peer_init, _, mut peer_resp, _) = connected_peers();
        let mut packet_data = vec![0u8; 1420];
        let mut packet = MutIpv4Packet::new(&mut packet_data[..]).unwrap();
        packet.set_version(4);
        b.iter_with_setup(move || {
            let (addr, packet) = peer_init.handle_outgoing_transport(packet.data()).expect("SETUP handle_outgoing_transport");
            let packet = packet.try_into().unwrap();
            (addr, packet)
        }, move |(addr, packet)| {
            peer_resp.handle_incoming_transport(addr, &packet).expect("handle_incoming_transport")
        });
    }).throughput(Throughput::Bytes(1420)));

//    c.bench("udp_send_to", Benchmark::new("udp_send_to", |b| {
////        let addr = SocketAddr::new(IpAddr::V6(Ipv4Addr::new(185, 112, 146, 247).to_ipv6_mapped()), 51820);
//        let addr = SocketAddr::new(IpAddr::V6(Ipv4Addr::new(127,0,0,1).to_ipv6_mapped()), 51820);
//        let socket = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp())).unwrap();
//        socket.set_only_v6(false).unwrap();
//        socket.bind(&SocketAddr::new("::".parse().unwrap(), 0).into()).unwrap();
//        let buf = [1u8; 1450];
//        b.iter(move || {
//            socket.send_to(&buf, &addr.into());
//        });
//    }).throughput(Throughput::Bytes(1450)));
//
//    c.bench("udp_send", Benchmark::new("udp_send", |b| {
////        let addr = SocketAddr::new(IpAddr::V6(Ipv4Addr::new(185, 112, 146, 247).to_ipv6_mapped()), 51820);
//        let addr = SocketAddr::new(IpAddr::V6(Ipv4Addr::new(127,0,0,1).to_ipv6_mapped()), 51820);
//        let socket = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp())).unwrap();
//        socket.set_only_v6(false).unwrap();
//        socket.bind(&SocketAddr::new("::".parse().unwrap(), 0).into()).unwrap();
//        let buf = [1u8; 1450];
//        socket.connect(&addr.into()).unwrap();
//        b.iter(move || {
//            socket.send(&buf);
//        });
//    }).throughput(Throughput::Bytes(1450)));
//
//    c.bench("udp_write", Benchmark::new("udp_send", |b| {
////        let addr = SocketAddr::new(IpAddr::V6(Ipv4Addr::new(185, 112, 146, 247).to_ipv6_mapped()), 51820);
//        let addr = SocketAddr::new(IpAddr::V6(Ipv4Addr::new(127,0,0,1).to_ipv6_mapped()), 51820);
//        let mut socket = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp())).unwrap();
//        socket.set_only_v6(false).unwrap();
//        socket.bind(&SocketAddr::new("::".parse().unwrap(), 0).into()).unwrap();
//        let buf = [1u8; 1450];
//        socket.connect(&addr.into()).unwrap();
//        b.iter(move || {
//            socket.write(&buf);
//        });
//    }).throughput(Throughput::Bytes(1450)));
}

fn custom_criterion() -> Criterion {
    Criterion::default().warm_up_time(Duration::new(1, 0)).measurement_time(Duration::new(3, 0))
}

criterion_group!(name = benches; config = custom_criterion(); targets = benchmarks);
criterion_main!(benches);
