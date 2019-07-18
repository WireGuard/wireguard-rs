use std::sync::Mutex;
use std::collections::HashMap;

use rand::prelude::*;
use rand::rngs::OsRng;

use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

use crate::noise;
use crate::messages;
use crate::types::*;
use crate::peer::Peer;

pub struct Device {
    pub sk : StaticSecret,              // static secret key
    pub pk : PublicKey,                 // static public key
    peers  : Vec<Peer>,                 // peer index  -> state
    pkmap  : HashMap<[u8; 32], usize>,  // public key  -> peer index
    ids    : Mutex<HashMap<u32, usize>> // receive ids -> peer index
}

/* A mutable reference to the state machine needs to be held,
 * during configuration.
 */
impl Device {
    /// Initialize a new handshake state machine
    ///
    /// # Arguments
    ///
    /// * `sk` - x25519 scalar representing the local private key
    pub fn new(sk : StaticSecret) -> Device {
        Device {
            pk    : PublicKey::from(&sk),
            sk    : sk,
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
    pub fn add(&mut self, pk : PublicKey) -> Result<(), ConfigError> {
        // check that the pk is not added twice

        if let Some(_) = self.pkmap.get(pk.as_bytes()) {
            return Err(ConfigError::new("Duplicate public key"));
        };

        // check that the pk is not that of the device

        if *self.pk.as_bytes() == *pk.as_bytes() {
            return Err(ConfigError::new("Public key corresponds to secret key of interface"));
        }

        // map : pk -> new index

        self.pkmap.insert(*pk.as_bytes(), self.peers.len());

        // map : new index -> peer

        self.peers.push(Peer::new(
            pk,
            self.sk.diffie_hellman(&pk)
        ));

        Ok(())
    }

    /// Add a psk to the peer
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key of the peer
    /// * `psk` - The psk to set / unset
    ///
    /// # Returns
    ///
    /// The call might fail if the public key is not found
    pub fn psk(&mut self, pk : PublicKey, psk : Option<Psk>) -> Result<(), ConfigError> {
        match self.pkmap.get(pk.as_bytes()) {
            Some(&idx) => {
                let peer = &mut self.peers[idx];
                peer.psk = match psk {
                    Some(v) => v,
                    None => [0u8; 32],
                };
                Ok(())
            },
            _ => Err(ConfigError::new("No such public key"))
        }
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
    pub fn begin(&self, pk : &PublicKey) -> Result<Vec<u8>, HandshakeError> {
        match self.pkmap.get(pk.as_bytes()) {
            None => Err(HandshakeError::UnknownPublicKey),
            Some(&idx) => {
                let peer = &self.peers[idx];
                let id = self.allocate(idx);
                noise::create_initiation(self, peer, id)
            }
        }
    }

    pub fn lookup(&self, pk : &PublicKey) -> Result<&Peer, HandshakeError> {
        match self.pkmap.get(pk.as_bytes()) {
            Some(&idx) => Ok(&self.peers[idx]),
            _ => Err(HandshakeError::UnknownPublicKey)
        }
    }

    /// Process a handshake message.
    ///
    /// # Arguments
    ///
    /// * `msg` - Byte slice containing the message (untrusted input)
    pub fn process(&self, msg : &[u8]) -> Result<Output, HandshakeError> {
        match msg.get(0) {
            Some(&messages::TYPE_INITIATION) => {
                noise::process_initiation(self, msg)
            },
            Some(&messages::TYPE_RESPONSE) => {
                Err(HandshakeError::InvalidMessageFormat)
            },
            _ => Err(HandshakeError::InvalidMessageFormat)
        }
    }
}

impl Device {
    // allocate a new index (id), for peer with idx
    fn allocate(&self, idx : usize) -> u32 {
        let mut rng = OsRng::new().unwrap();
        let mut table = self.ids.lock().unwrap();
        loop {
            let id = rng.gen();
            if !table.contains_key(&id) {
                table.insert(id, idx);
                return id;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake() {
        // generate new keypairs

        let mut rng = OsRng::new().unwrap();

        let sk1 = StaticSecret::new(&mut rng);
        let pk1 = PublicKey::from(&sk1);

        let sk2 = StaticSecret::new(&mut rng);
        let pk2 = PublicKey::from(&sk2);

        // intialize devices on both ends

        let mut dev1 = Device::new(sk1);
        let mut dev2 = Device::new(sk2);

        dev1.add(pk2).unwrap();
        dev2.add(pk1).unwrap();

        // create initiation

        let msg1 = dev1.begin(&pk2).unwrap();

        // process initiation and create response

        let out1 = dev2.process(&msg1).unwrap();

    }
}
