use spin::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use zerocopy::AsBytes;

use rand::prelude::*;

use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

use super::macs;
use super::messages::{CookieReply, Initiation, Response};
use super::messages::{TYPE_COOKIEREPLY, TYPE_INITIATION, TYPE_RESPONSE};
use super::noise;
use super::peer::Peer;
use super::types::*;

pub struct Device<T> {
    pub sk: StaticSecret,                   // static secret key
    pub pk: PublicKey,                      // static public key
    macs: macs::Validator,                  // validator for the mac fields
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
        let pk = PublicKey::from(&sk);
        Device {
            pk,
            sk,
            macs: macs::Validator::new(pk),
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
    pub fn set_psk(&mut self, pk: PublicKey, psk: Option<Psk>) -> Result<(), ConfigError> {
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

    /// Return the psk for the peer
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key of the peer
    ///
    /// # Returns
    ///
    /// A 32 byte array holding the PSK
    ///
    /// The call might fail if the public key is not found
    pub fn get_psk(&self, pk: PublicKey) -> Result<Psk, ConfigError> {
        match self.pk_map.get(pk.as_bytes()) {
            Some(peer) => Ok(peer.psk),
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
    pub fn begin<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        pk: &PublicKey,
    ) -> Result<Vec<u8>, HandshakeError> {
        match self.pk_map.get(pk.as_bytes()) {
            None => Err(HandshakeError::UnknownPublicKey),
            Some(peer) => {
                let sender = self.allocate(rng, peer);

                let mut msg = Initiation::default();

                noise::create_initiation(rng, self, peer, sender, &mut msg.noise)?;

                // add macs to initation

                peer.macs
                    .lock()
                    .generate(msg.noise.as_bytes(), &mut msg.macs);

                Ok(msg.as_bytes().to_owned())
            }
        }
    }

    /// Process a handshake message.
    ///
    /// # Arguments
    ///
    /// * `msg` - Byte slice containing the message (untrusted input)
    pub fn process<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        msg: &[u8],               // message buffer
        src: Option<&SocketAddr>, // optional source address, set when "under load"
    ) -> Result<Output<T>, HandshakeError> {
        match msg.get(0) {
            Some(&TYPE_INITIATION) => {
                // parse message
                let msg = Initiation::parse(msg)?;

                // check mac1 field
                self.macs.check_mac1(msg.noise.as_bytes(), &msg.macs)?;

                // check mac2 field
                if let Some(src) = src {
                    if !self.macs.check_mac2(msg.noise.as_bytes(), src, &msg.macs) {
                        let mut reply = Default::default();
                        self.macs.create_cookie_reply(
                            rng,
                            msg.noise.f_sender.get(),
                            src,
                            &msg.macs,
                            &mut reply,
                        );
                        return Ok((None, Some(reply.as_bytes().to_owned()), None));
                    }
                }

                // consume the initiation
                let (peer, st) = noise::consume_initiation(self, &msg.noise)?;

                // allocate new index for response
                let sender = self.allocate(rng, peer);

                // prepare memory for response, TODO: take slice for zero allocation
                let mut resp = Response::default();

                // create response (release id on error)
                let keys = noise::create_response(rng, peer, sender, st, &mut resp.noise).map_err(
                    |e| {
                        self.release(sender);
                        e
                    },
                )?;

                // add macs to response
                peer.macs
                    .lock()
                    .generate(resp.noise.as_bytes(), &mut resp.macs);

                // return unconfirmed keypair and the response as vector
                Ok((
                    Some(peer.identifier),
                    Some(resp.as_bytes().to_owned()),
                    Some(keys),
                ))
            }
            Some(&TYPE_RESPONSE) => {
                let msg = Response::parse(msg)?;

                // check mac1 field
                self.macs.check_mac1(msg.noise.as_bytes(), &msg.macs)?;

                // check mac2 field
                if let Some(src) = src {
                    if !self.macs.check_mac2(msg.noise.as_bytes(), src, &msg.macs) {
                        let mut reply = Default::default();
                        self.macs.create_cookie_reply(
                            rng,
                            msg.noise.f_sender.get(),
                            src,
                            &msg.macs,
                            &mut reply,
                        );
                        return Ok((None, Some(reply.as_bytes().to_owned()), None));
                    }
                }

                // consume inner playload
                noise::consume_response(self, &msg.noise)
            }
            Some(&TYPE_COOKIEREPLY) => {
                let msg = CookieReply::parse(msg)?;

                // lookup peer
                let peer = self.lookup_id(msg.f_receiver.get())?;

                // validate cookie reply
                peer.macs.lock().process(&msg)?;

                // this prompts no new message and
                // DOES NOT cryptographically verify the peer
                Ok((None, None, None))
            }
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
    fn allocate<R: RngCore + CryptoRng>(&self, rng: &mut R, peer: &Peer<T>) -> u32 {
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
    use super::super::messages::*;
    use super::*;
    use hex;
    use rand::rngs::OsRng;

    #[test]
    fn handshake() {
        // generate new keypairs

        let mut rng = OsRng::new().unwrap();

        let sk1 = StaticSecret::new(&mut rng);
        let pk1 = PublicKey::from(&sk1);

        let sk2 = StaticSecret::new(&mut rng);
        let pk2 = PublicKey::from(&sk2);

        // pick random psk

        let mut psk = [0u8; 32];
        rng.fill_bytes(&mut psk[..]);

        // intialize devices on both ends

        let mut dev1 = Device::new(sk1);
        let mut dev2 = Device::new(sk2);

        dev1.add(pk2, 1337).unwrap();
        dev2.add(pk1, 2600).unwrap();

        dev1.set_psk(pk2, Some(psk)).unwrap();
        dev2.set_psk(pk1, Some(psk)).unwrap();

        // do a few handshakes

        for i in 0..10 {
            println!("handshake : {}", i);

            // create initiation

            let msg1 = dev1.begin(&mut rng, &pk2).unwrap();

            println!("msg1 = {} : {} bytes", hex::encode(&msg1[..]), msg1.len());
            println!("msg1 = {:?}", Initiation::parse(&msg1[..]).unwrap());

            // process initiation and create response

            let (_, msg2, ks_r) = dev2.process(&mut rng, &msg1, None).unwrap();

            let ks_r = ks_r.unwrap();
            let msg2 = msg2.unwrap();

            println!("msg2 = {} : {} bytes", hex::encode(&msg2[..]), msg2.len());
            println!("msg2 = {:?}", Response::parse(&msg2[..]).unwrap());

            assert!(!ks_r.confirmed, "Responders key-pair is confirmed");

            // process response and obtain confirmed key-pair

            let (_, msg3, ks_i) = dev1.process(&mut rng, &msg2, None).unwrap();
            let ks_i = ks_i.unwrap();

            assert!(msg3.is_none(), "Returned message after response");
            assert!(ks_i.confirmed, "Initiators key-pair is not confirmed");

            assert_eq!(ks_i.send, ks_r.recv, "KeyI.send != KeyR.recv");
            assert_eq!(ks_i.recv, ks_r.send, "KeyI.recv != KeyR.send");

            dev1.release(ks_i.send.id);
            dev2.release(ks_r.send.id);
        }

        assert_eq!(dev1.get_psk(pk2).unwrap(), psk);
        assert_eq!(dev2.get_psk(pk1).unwrap(), psk);

        dev1.remove(pk2).unwrap();
        dev2.remove(pk1).unwrap();
    }
}
