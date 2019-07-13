use std::sync::Mutex;

use x25519_dalek::PublicKey;
use x25519_dalek::SharedSecret;

struct Key {
    key : [u8; 32],
    id  : u32
}

pub struct KeyPair {
    confimed : bool, // has the key-pair been confirmed?
    send     : Key,  // key for outbound messages
    recv     : Key   // key for inbound messages
}

pub struct Output (
    Option<KeyPair>, // resulting key-pair of successful handshake
    Option<Vec<u8>>  // message to send
);

pub struct Peer {
    // mutable state
    pub m   : Mutex<State>,

    // constant state
    pub pk  : PublicKey,     // public key of peer
    pub ss  : SharedSecret,  // precomputed DH(static, static)
    pub psk : [u8; 32]       // psk of peer
}

pub enum State {
    Reset,
    InitiationSent,
}
