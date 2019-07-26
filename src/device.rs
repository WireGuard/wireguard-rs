use spin::RwLock;
use std::collections::HashMap;

use rand::prelude::*;
use rand::rngs::OsRng;

use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

use crate::messages;
use crate::noise;
use crate::peer::Peer;
use crate::types::*;

pub struct Device<T> {
    pub sk: StaticSecret,                   // static secret key
    pub pk: PublicKey,                      // static public key
    pk_map: HashMap<[u8; 32], Peer<T>>,     // public key  -> peer state
    id_map: RwLock<HashMap<u32, [u8; 32]>>, // receiver ids -> public key
}

/* A mutable reference to the device needs to be held during configuration.
 * Wrapping the device in a RwLock enables peer config after "configuration time"
 */
impl<T> Device<T>
where
    T: Copy,
{
    /// Initialize a new handshake state machine
    ///
    /// # Arguments
    ///
    /// * `sk` - x25519 scalar representing the local private key
    pub fn new(sk: StaticSecret) -> Device<T> {
        Device {
            pk: PublicKey::from(&sk),
            sk: sk,
            pk_map: HashMap::new(),
            id_map: RwLock::new(HashMap::new()),
        }
    }

    /// Add a new public key to the state machine
    /// To remove public keys, you must create a new machine instance
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key to add
    /// * `identifier` - Associated identifier which can be used to distinguish the peers
    pub fn add(&mut self, pk: PublicKey, identifier: T) -> Result<(), ConfigError> {
        // check that the pk is not added twice

        if let Some(_) = self.pk_map.get(pk.as_bytes()) {
            return Err(ConfigError::new("Duplicate public key"));
        };

        // check that the pk is not that of the device

        if *self.pk.as_bytes() == *pk.as_bytes() {
            return Err(ConfigError::new(
                "Public key corresponds to secret key of interface",
            ));
        }

        // map : pk -> new index

        self.pk_map.insert(
            *pk.as_bytes(),
            Peer::new(identifier, pk, self.sk.diffie_hellman(&pk)),
        );

        Ok(())
    }

    /// Remove a peer by public key
    /// To remove public keys, you must create a new machine instance
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key of the peer to remove
    ///
    /// # Returns
    ///
    /// The call might fail if the public key is not found
    pub fn remove(&mut self, pk: PublicKey) -> Result<(), ConfigError> {
        // take write-lock on receive id table
        let mut id_map = self.id_map.write();

        // remove the peer
        self.pk_map
            .remove(pk.as_bytes())
            .ok_or(ConfigError::new("Public key not in device"))?;

        // pruge the id map (linear scan)
        id_map.retain(|_, v| v != pk.as_bytes());
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
    pub fn psk(&mut self, pk: PublicKey, psk: Option<Psk>) -> Result<(), ConfigError> {
        match self.pk_map.get_mut(pk.as_bytes()) {
            Some(mut peer) => {
                peer.psk = match psk {
                    Some(v) => v,
                    None => [0u8; 32],
                };
                Ok(())
            }
            _ => Err(ConfigError::new("No such public key")),
        }
    }

    /// Release an id back to the pool
    ///
    /// # Arguments
    ///
    /// * `id` - The (sender) id to release
    pub fn release(&self, id: u32) {
        let mut m = self.id_map.write();
        debug_assert!(m.contains_key(&id), "Releasing id not allocated");
        m.remove(&id);
    }

    /// Begin a new handshake
    ///
    /// # Arguments
    ///
    /// * `pk` - Public key of peer to initiate handshake for
    pub fn begin(&self, pk: &PublicKey) -> Result<Vec<u8>, HandshakeError> {
        match self.pk_map.get(pk.as_bytes()) {
            None => Err(HandshakeError::UnknownPublicKey),
            Some(peer) => {
                let sender = self.allocate(peer);
                noise::create_initiation(self, peer, sender)
            }
        }
    }

    /// Process a handshake message.
    ///
    /// # Arguments
    ///
    /// * `msg` - Byte slice containing the message (untrusted input)
    pub fn process(&self, msg: &[u8]) -> Result<Output<T>, HandshakeError> {
        match msg.get(0) {
            Some(&messages::TYPE_INITIATION) => {
                // consume the initiation
                let (peer, st) = noise::consume_initiation(self, msg)?;

                // allocate new index for response
                let sender = self.allocate(peer);

                // create response (release id on error)
                noise::create_response(peer, sender, st).map_err(|e| {
                    self.release(sender);
                    e
                })
            }
            Some(&messages::TYPE_RESPONSE) => noise::consume_response(self, msg),
            _ => Err(HandshakeError::InvalidMessageFormat),
        }
    }

    // Internal function
    //
    // Return the peer associated with the public key
    pub(crate) fn lookup_pk(&self, pk: &PublicKey) -> Result<&Peer<T>, HandshakeError> {
        self.pk_map
            .get(pk.as_bytes())
            .ok_or(HandshakeError::UnknownPublicKey)
    }

    // Internal function
    //
    // Return the peer currently associated with the receiver identifier
    pub(crate) fn lookup_id(&self, id: u32) -> Result<&Peer<T>, HandshakeError> {
        let im = self.id_map.read();
        let pk = im.get(&id).ok_or(HandshakeError::UnknownReceiverId)?;
        match self.pk_map.get(pk) {
            Some(peer) => Ok(peer),
            _ => unreachable!(), // if the id-lookup succeeded, the peer should exist
        }
    }

    // Internal function
    //
    // Allocated a new receiver identifier for the peer
    fn allocate(&self, peer: &Peer<T>) -> u32 {
        let mut rng = OsRng::new().unwrap();

        loop {
            let id = rng.gen();

            // check membership with read lock
            if self.id_map.read().contains_key(&id) {
                continue;
            }

            // take write lock and add index
            let mut m = self.id_map.write();
            if !m.contains_key(&id) {
                m.insert(id, *peer.pk.as_bytes());
                return id;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use messages::*;

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

        dev1.add(pk2, 1337).unwrap();
        dev2.add(pk1, 2600).unwrap();

        // do a few handshakes

        for i in 0..10 {
            println!("handshake : {}", i);

            // create initiation

            let msg1 = dev1.begin(&pk2).unwrap();

            println!("msg1 = {}", hex::encode(&msg1[..]));
            println!("msg1 = {:?}", Initiation::parse(&msg1[..]).unwrap());

            // process initiation and create response

            let (_, msg2, ks_r) = dev2.process(&msg1).unwrap();

            let ks_r = ks_r.unwrap();
            let msg2 = msg2.unwrap();

            println!("msg2 = {}", hex::encode(&msg2[..]));
            println!("msg2 = {:?}", Response::parse(&msg2[..]).unwrap());

            assert!(!ks_r.confirmed, "Responders key-pair is confirmed");

            // process response and obtain confirmed key-pair

            let (_, msg3, ks_i) = dev1.process(&msg2).unwrap();
            let ks_i = ks_i.unwrap();

            assert!(msg3.is_none(), "Returned message after response");
            assert!(ks_i.confirmed, "Initiators key-pair is not confirmed");

            assert_eq!(ks_i.send, ks_r.recv, "KeyI.send != KeyR.recv");
            assert_eq!(ks_i.recv, ks_r.send, "KeyI.recv != KeyR.send");

            dev1.release(ks_i.send.id);
            dev2.release(ks_r.send.id);
        }
    }
}
