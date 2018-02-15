#[macro_use]
extern crate criterion;
extern crate wireguard;
extern crate x25519_dalek;
extern crate rand;
extern crate snow;

use criterion::Criterion;
use wireguard::protocol::Peer;
use wireguard::noise::Noise;
use x25519_dalek::{generate_secret, generate_public};
use rand::OsRng;

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
    let mut peer_init = Peer::default();
    let mut peer_resp = Peer::default();
    let     init_keys = Keypair::new();
    let     resp_keys = Keypair::new();
    let mut initiator = Noise::build_initiator(&init_keys.private, &resp_keys.public, &None).unwrap();
    let mut responder = Noise::build_responder(&resp_keys.private).unwrap();
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

    peer_init.sessions.current = Some(initiator.into_transport_mode().unwrap().into());
    peer_resp.sessions.current = Some(responder.into_transport_mode().unwrap().into());
    peer_init.info.pub_key = resp_keys.public;
    peer_resp.info.pub_key = init_keys.public;
    (peer_init, init_keys.private, peer_resp, resp_keys.private)
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("peer_handshake_initialization", |b| {
        let mut peer = Peer::default();
        b.iter(move || {
            peer.initiate_new_session(&[1u8; 32]).unwrap()
        });
    });

    c.bench_function("peer_handshake_response", |b| {
        let (mut peer_init, init_priv, mut peer_resp, resp_priv) = connected_peers();
        let (init, _) = peer_init.initiate_new_session(&init_priv).expect("initiate");
        let addr = ([127, 0, 0, 1], 443).into();
        b.iter(move || {
            peer_resp.last_handshake_tai64n = None;
            let handshake = Peer::process_incoming_handshake(&resp_priv, &init).unwrap();
            peer_resp.complete_incoming_handshake(, handshake).expect("second half");
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
