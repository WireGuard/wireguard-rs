use std::fmt;
use std::sync::Mutex;
use std::error::Error;

use x25519_dalek::PublicKey;
use x25519_dalek::SharedSecret;

use generic_array::typenum::U32;
use generic_array::GenericArray;

use crate::timestamp;

// config error

#[derive(Debug)]
pub struct ConfigError(String);

impl ConfigError {
    pub fn new(s : &str) -> Self {
        ConfigError(s.to_string())
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConfigError({})", self.0)
    }
}

impl Error for ConfigError {
    fn description(&self) -> &str {
        &self.0
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

// handshake error

#[derive(Debug)]
pub struct HandshakeError {}

impl HandshakeError {
    pub fn new() -> Self {
        HandshakeError{}
    }
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HandshakeError")
    }
}

impl Error for HandshakeError {
    fn description(&self) -> &str {
        "Generic Handshake Error"
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

// types for resulting key-material

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

// per-peer state machine

pub type Psk = [u8; 32];

pub struct Peer {
    // mutable state
    pub state : Mutex<State>,

    // constant state
    pub pk    : PublicKey,     // public key of peer
    pub ss    : SharedSecret,  // precomputed DH(static, static)
    pub psk   : Psk            // psk of peer
}

pub enum State {
    Reset{
        ts : Option<timestamp::TAI64N>
    },
    InitiationSent{
        hs : GenericArray<u8, U32>,
        ck : GenericArray<u8, U32>
    },
}
