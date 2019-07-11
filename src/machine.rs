use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;
use x25519_dalek::SharedSecret;

use std::sync::Mutex;
use std::sync::mpsc::channel;
use std::collections::HashMap;

pub struct Peer {
    m   : StateMutable,
    sk  : StaticSecret,
    pk  : PublicKey,
    ss  : SharedSecret,
    psk : [u8; 32]
}

/* Mutable part of handshake state */
enum StateMutable {
    Reset,
    InitiationSent,
    InitiationProcessed,
    ReponseSent
}

/* Immutable part of the handshake state */
struct StateFixed {
}

struct StateMachine {
    peers : Vec<Mutex<Peer>>,          // peer index  -> state
    pkmap : HashMap<[u8; 32], usize>,  // public key  -> peer index
    ids   : Mutex<HashMap<u32, usize>> // receive ids -> peer index
}

struct Key {
    key : [u8; 32],
    id  : u32
}

struct KeyPair {
    confimed : bool, // has the key-pair been confirmed
    send     : Key,  // key for outbound messages
    recv     : Key   // key for inbound messages
}

struct Output (
    Option<KeyPair>, // resulting key-pair of successful handshake
    Option<u32>      // id to be released
);

impl StateMachine {
    /// Initialize a new handshake state machine
    ///
    /// # Arguments
    ///
    /// * `sk` - x25519 scalar representing the local private key
    pub fn new(sk : StaticSecret) -> StateMachine {
        StateMachine {
            peers : vec![],
            pkmap : HashMap::new(),
            ids   : Mutex::new(HashMap::new())
        }
    }

    /// Add a new public key to the state machine
    /// To remove public keys, you must create a new machine instance
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key to add
    ///
    /// # Returns
    ///
    /// The call might fail if the public key corresponds to the secret key of the machine
    pub fn add(&mut self, pk : PublicKey) -> Result<(), ()> {
        // let ss = sk.diffie_hellman(&pk);
        Err(())
    }

    /// Release an id back to the pool
    ///
    /// # Arguments
    ///
    /// * `id` - The (sender) id to release
    pub fn release(&self, id : u32) {
        self.ids.lock().unwrap().remove(&id);
    }

    /// Begin a new handshake
    ///
    /// # Arguments
    ///
    /// * `pk` - Public key of peer to initiate handshake for
    pub fn begin(&self, pk : PublicKey) -> Result<Output, ()> {
        match self.pkmap.get(pk.as_bytes()) {
            None => Err(()),
            Some(&idx) => {
                let mut peer = self.peers.get(idx).unwrap().lock().unwrap();
                Err(())
            }
        }
    }

    /// Process a handshake message.
    ///
    /// # Arguments
    ///
    /// * `msg` - Byte slice containing the message (untrusted input)
    fn process(&self, msg : &[u8]) -> Result<Output, ()> {
        // inspect type field
        match msg.get(0) {
            _ => Err(())
        }
    }
}
