use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};
use spin::RwLock;
use std::time::{Duration, Instant};

// types to coalesce into bytes
use std::net::SocketAddr;
use x25519_dalek::PublicKey;

// AEAD

use aead::{Aead, NewAead, Payload};
use chacha20poly1305::XChaCha20Poly1305;

// MAC
use blake2::Blake2s;
use subtle::ConstantTimeEq;

use super::messages::{CookieReply, MacsFooter, TYPE_COOKIE_REPLY};
use super::types::HandshakeError;

const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";

const SIZE_COOKIE: usize = 16;
const SIZE_SECRET: usize = 32;
const SIZE_MAC: usize = 16; // blake2s-mac128
const SIZE_TAG: usize = 16; // xchacha20poly1305 tag

const COOKIE_UPDATE_INTERVAL: Duration = Duration::from_secs(120);

macro_rules! HASH {
    ( $($input:expr),* ) => {{
        use blake2::Digest;
        let mut hsh = Blake2s::new();
        $(
            hsh.update($input);
        )*
        hsh.finalize()
    }};
}

macro_rules! MAC {
    ( $key:expr, $($input:expr),* ) => {{
        use blake2::VarBlake2s;
        use blake2::digest::{Update, VariableOutput};
        let mut tag = [0u8; SIZE_MAC];
        let mut mac = VarBlake2s::new_keyed($key, SIZE_MAC);
        $(
            mac.update($input);
        )*
        mac.finalize_variable(|buf| tag.copy_from_slice(buf));
        tag
    }};
}

macro_rules! XSEAL {
    ($key:expr, $nonce:expr, $ad:expr, $pt:expr, $ct:expr) => {{
        let ct = XChaCha20Poly1305::new(GenericArray::from_slice($key))
            .encrypt(
                GenericArray::from_slice($nonce),
                Payload { msg: $pt, aad: $ad },
            )
            .unwrap();
        debug_assert_eq!(ct.len(), $pt.len() + SIZE_TAG);
        $ct.copy_from_slice(&ct);
    }};
}

macro_rules! XOPEN {
    ($key:expr, $nonce:expr, $ad:expr, $pt:expr, $ct:expr) => {{
        debug_assert_eq!($ct.len(), $pt.len() + SIZE_TAG);
        XChaCha20Poly1305::new(GenericArray::from_slice($key))
            .decrypt(
                GenericArray::from_slice($nonce),
                Payload { msg: $ct, aad: $ad },
            )
            .map_err(|_| HandshakeError::DecryptionFailure)
            .map(|pt| $pt.copy_from_slice(&pt))
    }};
}

struct Cookie {
    value: [u8; 16],
    birth: Instant,
}

pub struct Generator {
    mac1_key: [u8; 32],
    cookie_key: [u8; 32], // xchacha20poly key for opening cookie response
    last_mac1: Option<[u8; 16]>,
    cookie: Option<Cookie>,
}

fn addr_to_mac_bytes(addr: &SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(addr) => {
            let mut res = Vec::with_capacity(4 + 2);
            res.extend(&addr.ip().octets());
            res.extend(&addr.port().to_le_bytes());
            res
        }
        SocketAddr::V6(addr) => {
            let mut res = Vec::with_capacity(16 + 2);
            res.extend(&addr.ip().octets());
            res.extend(&addr.port().to_le_bytes());
            res
        }
    }
}

impl Generator {
    /// Initalize a new mac field generator
    ///
    /// # Arguments
    ///
    /// - pk: The public key of the peer to which the generator is associated
    ///
    /// # Returns
    ///
    /// A freshly initated generator
    pub fn new(pk: PublicKey) -> Generator {
        Generator {
            mac1_key: HASH!(LABEL_MAC1, pk.as_bytes()).into(),
            cookie_key: HASH!(LABEL_COOKIE, pk.as_bytes()).into(),
            last_mac1: None,
            cookie: None,
        }
    }

    /// Process a CookieReply message
    ///
    /// # Arguments
    ///
    /// - reply: CookieReply to process
    ///
    /// # Returns
    ///
    /// Can fail if the cookie reply fails to validate
    /// (either indicating that it is outdated or malformed)
    pub fn process(&mut self, reply: &CookieReply) -> Result<(), HandshakeError> {
        let mac1 = self.last_mac1.ok_or(HandshakeError::InvalidState)?;
        let mut tau = [0u8; SIZE_COOKIE];
        #[allow(clippy::unnecessary_mut_passed)]
        XOPEN!(
            &self.cookie_key, // key
            &reply.f_nonce,   // nonce
            &mac1,            // ad
            &mut tau,         // pt
            &reply.f_cookie   // ct || tag
        )?;
        self.cookie = Some(Cookie {
            birth: Instant::now(),
            value: tau,
        });
        Ok(())
    }

    /// Generate both mac fields for an inner message
    ///
    /// # Arguments
    ///
    /// - inner: A byteslice representing the inner message to be covered
    /// - macs: The destination mac footer for the resulting macs
    pub fn generate(&mut self, inner: &[u8], macs: &mut MacsFooter) {
        macs.f_mac1 = MAC!(&self.mac1_key, inner);
        macs.f_mac2 = match &self.cookie {
            Some(cookie) => {
                if cookie.birth.elapsed() > COOKIE_UPDATE_INTERVAL {
                    self.cookie = None;
                    [0u8; SIZE_MAC]
                } else {
                    MAC!(&cookie.value, inner, macs.f_mac1)
                }
            }
            None => [0u8; SIZE_MAC],
        };
        self.last_mac1 = Some(macs.f_mac1);
    }
}

struct Secret {
    value: [u8; 32],
    birth: Instant,
}

pub struct Validator {
    mac1_key: [u8; 32],   // mac1 key, derived from device public key
    cookie_key: [u8; 32], // xchacha20poly key for sealing cookie response
    secret: RwLock<Secret>,
}

impl Validator {
    pub fn new(pk: PublicKey) -> Validator {
        Validator {
            mac1_key: HASH!(LABEL_MAC1, pk.as_bytes()).into(),
            cookie_key: HASH!(LABEL_COOKIE, pk.as_bytes()).into(),
            secret: RwLock::new(Secret {
                value: [0u8; SIZE_SECRET],
                birth: Instant::now() - Duration::new(86400, 0),
            }),
        }
    }

    fn get_tau(&self, src: &[u8]) -> Option<[u8; SIZE_COOKIE]> {
        let secret = self.secret.read();
        if secret.birth.elapsed() < COOKIE_UPDATE_INTERVAL {
            Some(MAC!(&secret.value, src))
        } else {
            None
        }
    }

    fn get_set_tau<R: RngCore + CryptoRng>(&self, rng: &mut R, src: &[u8]) -> [u8; SIZE_COOKIE] {
        // check if current value is still valid
        {
            let secret = self.secret.read();
            if secret.birth.elapsed() < COOKIE_UPDATE_INTERVAL {
                return MAC!(&secret.value, src);
            };
        }

        // take write lock, check again
        {
            let mut secret = self.secret.write();
            if secret.birth.elapsed() < COOKIE_UPDATE_INTERVAL {
                return MAC!(&secret.value, src);
            };

            // set new random cookie secret
            rng.fill_bytes(&mut secret.value);
            secret.birth = Instant::now();
            MAC!(&secret.value, src)
        }
    }

    pub fn create_cookie_reply<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        receiver: u32,         // receiver id of incoming message
        src: &SocketAddr,      // source address of incoming message
        macs: &MacsFooter,     // footer of incoming message
        msg: &mut CookieReply, // resulting cookie reply
    ) {
        let src = addr_to_mac_bytes(src);
        msg.f_type.set(TYPE_COOKIE_REPLY as u32);
        msg.f_receiver.set(receiver);
        rng.fill_bytes(&mut msg.f_nonce);
        XSEAL!(
            &self.cookie_key,             // key
            &msg.f_nonce,                 // nonce
            &macs.f_mac1,                 // ad
            &self.get_set_tau(rng, &src), // pt
            &mut msg.f_cookie             // ct || tag
        );
    }

    /// Check the mac1 field against the inner message
    ///
    /// # Arguments
    ///
    /// - inner: The inner message covered by the mac1 field
    /// - macs: The mac footer
    pub fn check_mac1(&self, inner: &[u8], macs: &MacsFooter) -> Result<(), HandshakeError> {
        let valid_mac1: bool = MAC!(&self.mac1_key, inner).ct_eq(&macs.f_mac1).into();
        if !valid_mac1 {
            Err(HandshakeError::InvalidMac1)
        } else {
            Ok(())
        }
    }

    pub fn check_mac2(&self, inner: &[u8], src: &SocketAddr, macs: &MacsFooter) -> bool {
        let src = addr_to_mac_bytes(src);
        match self.get_tau(&src) {
            Some(tau) => MAC!(&tau, inner, macs.f_mac1).ct_eq(&macs.f_mac2).into(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand::rngs::OsRng;
    use x25519_dalek::StaticSecret;

    fn new_validator_generator() -> (Validator, Generator) {
        let sk = StaticSecret::new(&mut OsRng);
        let pk = PublicKey::from(&sk);
        (Validator::new(pk), Generator::new(pk))
    }

    proptest! {
        #[test]
        fn test_cookie_reply(inner1 : Vec<u8>, inner2 : Vec<u8>, receiver : u32) {
            let mut msg = CookieReply::default();
            let mut macs = MacsFooter::default();
            let src = "192.0.2.16:8080".parse().unwrap();
            let (validator, mut generator) = new_validator_generator();

            // generate mac1 for first message
            generator.generate(&inner1[..], &mut macs);
            assert_ne!(macs.f_mac1, [0u8; SIZE_MAC], "mac1 should be set");
            assert_eq!(macs.f_mac2, [0u8; SIZE_MAC], "mac2 should not be set");

            // check validity of mac1
            validator.check_mac1(&inner1[..], &macs).expect("mac1 of inner1 did not validate");
            assert_eq!(validator.check_mac2(&inner1[..], &src, &macs), false, "mac2 of inner2 did not validate");
            validator.create_cookie_reply(&mut OsRng, receiver, &src, &macs, &mut msg);

            // consume cookie reply
            generator.process(&msg).expect("failed to process CookieReply");

            // generate mac2 & mac2 for second message
            generator.generate(&inner2[..], &mut macs);
            assert_ne!(macs.f_mac1, [0u8; SIZE_MAC], "mac1 should be set");
            assert_ne!(macs.f_mac2, [0u8; SIZE_MAC], "mac2 should be set");

            // check validity of mac1 and mac2
            validator.check_mac1(&inner2[..], &macs).expect("mac1 of inner2 did not validate");
            assert!(validator.check_mac2(&inner2[..], &src, &macs), "mac2 of inner2 did not validate");
        }
    }
}
