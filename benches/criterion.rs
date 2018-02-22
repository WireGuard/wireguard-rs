#[macro_use]
extern crate criterion;
extern crate wireguard;
extern crate x25519_dalek;
extern crate rand;
extern crate snow;
extern crate pnet;

use criterion::{Benchmark, Criterion, Throughput};
use wireguard::peer::{Peer, Session};
use wireguard::noise;
use x25519_dalek::{generate_secret, generate_public};
use rand::OsRng;
use std::time::Duration;
use pnet::packet::{Packet, ipv4::MutableIpv4Packet};

struct Keypair {
    pub private: [u8; 32],
    pub public: [u8; 32]
}

impl Keypair {
    pub fn new() -> Keypair {
        let mut rng     = OsRng::new().unwrap();
        let     private = generate_secret(&mut rng);
        let     public  = generate_public(&private).to_bytes();

        Keypair{ private, public}

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

    let mut init_session = Session::from(initiator.into_transport_mode().unwrap());
    let     resp_session = Session::with_their_index(responder.into_transport_mode().unwrap(), init_session.our_index);
    init_session.their_index = resp_session.our_index;

    peer_init.sessions.current = Some(init_session);
    peer_init.info.endpoint = Some(([127, 0, 0, 1], 443).into());
    peer_init.info.pub_key = resp_keys.public;

    peer_resp.sessions.current = Some(resp_session);
    peer_resp.info.endpoint = Some(([127, 0, 0, 1], 443).into());
    peer_resp.info.pub_key = init_keys.public;

    (peer_init, init_keys.private, peer_resp, resp_keys.private)
}

fn benchmarks(c: &mut Criterion) {
    c.bench("peer_handshake_initialization", Benchmark::new("peer_handshake_initialization", |b| {
        let (mut peer, _, _, _) = connected_peers();
        b.iter(move || {
            peer.initiate_new_session(&[1u8; 32]).unwrap()
        });
    }).throughput(Throughput::Elements(1)));

    c.bench("peer_handshake_response", Benchmark::new("peer_handshake_response", |b| {
        let (mut peer_init, init_priv, mut peer_resp, resp_priv) = connected_peers();
        let (_, init, _, _) = peer_init.initiate_new_session(&init_priv).expect("initiate");
        let addr = ([127, 0, 0, 1], 443).into();
        b.iter(move || {
            peer_resp.last_handshake_tai64n = None;
            let handshake = Peer::process_incoming_handshake(&resp_priv, &init).unwrap();
            peer_resp.complete_incoming_handshake(addr, handshake).expect("second half");
        });
    }).throughput(Throughput::Elements(1)));

    c.bench("peer_transport_outgoing", Benchmark::new("peer_transport_outgoing", |b| {
        let (mut peer_init, _, _, _) = connected_peers();
        b.iter(move || {
            peer_init.handle_outgoing_transport(&[1u8; 1420]).expect("handle_outgoing_transport")
        });
    }).throughput(Throughput::Bytes(1452)));

    c.bench("peer_transport_incoming", Benchmark::new("peer_transport_incoming", |b| {
        let (mut peer_init, _, mut peer_resp, _) = connected_peers();
        let mut packet = MutableIpv4Packet::owned(vec![0u8; 1420]).unwrap();
        packet.set_version(4);
        b.iter_with_setup(move || {
            peer_init.handle_outgoing_transport(packet.packet()).expect("SETUP handle_outgoing_transport")
        }, move |(addr, packet)| {
            peer_resp.handle_incoming_transport(addr, &packet).expect("handle_incoming_transport")
        });
    }).throughput(Throughput::Bytes(1452)));
}

fn custom_criterion() -> Criterion {
    Criterion::default().warm_up_time(Duration::new(1, 0)).measurement_time(Duration::new(3, 0))
}

criterion_group!(name = benches; config = custom_criterion(); targets = benchmarks);
criterion_main!(benches);
