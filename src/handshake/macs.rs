use std::time::{Duration, Instant};

use rand::CryptoRng;
use rand::RngCore;

use spin::Mutex;

use blake2::Blake2s;
use subtle::ConstantTimeEq;
use x25519_dalek::PublicKey;

use sodiumoxide::crypto::aead::xchacha20poly1305_ietf;

use super::messages::{CookieReply, MacsFooter};
use super::types::HandshakeError;

const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";

const SIZE_COOKIE: usize = 16;
const SIZE_SECRET: usize = 32;
const SIZE_MAC: usize = 16; // blake2s-mac128

const SECS_COOKIE_UPDATE: u64 = 120;

macro_rules! HASH {
    ( $($input:expr),* ) => {{
        use blake2::Digest;
        let mut hsh = Blake2s::new();
        $(
            hsh.input($input);
        )*
        hsh.result()
    }};
}

macro_rules! MAC {
    ( $key:expr, $($input:expr),* ) => {{
        use blake2::VarBlake2s;
        use digest::Input;
        use digest::VariableOutput;
        let mut tag = [0u8; SIZE_MAC];
        let mut mac = VarBlake2s::new_keyed($key, SIZE_MAC);
        $(
            mac.input($input);
        )*
        mac.variable_result(|buf| tag.copy_from_slice(buf));
        tag
    }};
}

macro_rules! XSEAL {
    ($key:expr, $nonce:expr, $ad:expr, $pt:expr, $ct:expr, $tag:expr) => {{
        let s_key = xchacha20poly1305_ietf::Key::from_slice($key).unwrap();
        let s_nonce = xchacha20poly1305_ietf::Nonce::from_slice($nonce).unwrap();

        debug_assert_eq!($tag.len(), xchacha20poly1305_ietf::TAGBYTES);
        debug_assert_eq!($pt.len(), $ct.len());

        $ct.copy_from_slice($pt);
        let tag = xchacha20poly1305_ietf::seal_detached(
            $ct,
            if $ad.len() == 0 { None } else { Some($ad) },
            &s_nonce,
            &s_key,
        );
        $tag.copy_from_slice(tag.as_ref());
    }};
}

macro_rules! XOPEN {
    ($key:expr, $nonce:expr, $ad:expr, $pt:expr, $ct:expr, $tag:expr) => {{
        let s_key = xchacha20poly1305_ietf::Key::from_slice($key).unwrap();
        let s_nonce = xchacha20poly1305_ietf::Nonce::from_slice($nonce).unwrap();
        let s_tag = xchacha20poly1305_ietf::Tag::from_slice($tag).unwrap();

        debug_assert_eq!($pt.len(), $ct.len());

        $pt.copy_from_slice($ct);
        xchacha20poly1305_ietf::open_detached(
            $pt,
            if $ad.len() == 0 { None } else { Some($ad) },
            &s_tag,
            &s_nonce,
            &s_key,
        )
        .map_err(|_| HandshakeError::DecryptionFailure)
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
        XOPEN!(
            &self.cookie_key,    // key
            &reply.f_nonce,      // nonce
            &mac1,               // ad
            &mut tau,            // pt
            &reply.f_cookie,     // ct
            &reply.f_cookie_tag  // tag
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
                if cookie.birth.elapsed() > Duration::from_secs(SECS_COOKIE_UPDATE) {
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
    mac1_key: [u8; 32],
    cookie_key: [u8; 32], // xchacha20poly key for sealing cookie response
    secret: Mutex<Secret>,
}

impl Validator {
    pub fn new(pk: PublicKey) -> Validator {
        Validator {
            mac1_key: HASH!(LABEL_MAC1, pk.as_bytes()).into(),
            cookie_key: HASH!(LABEL_COOKIE, pk.as_bytes()).into(),
            secret: Mutex::new(Secret {
                value: [0u8; SIZE_SECRET],
                birth: Instant::now() - Duration::from_secs(2 * SECS_COOKIE_UPDATE),
            }),
        }
    }

    fn get_tau(&self, src: &[u8]) -> Result<[u8; SIZE_COOKIE], HandshakeError> {
        let secret = self.secret.lock();
        if secret.birth.elapsed() < Duration::from_secs(SECS_COOKIE_UPDATE) {
            Ok(MAC!(&secret.value, src))
        } else {
            Err(HandshakeError::InvalidMac2)
        }
    }

    fn get_set_tau<T>(&self, rng: &mut T, src: &[u8]) -> [u8; SIZE_COOKIE]
    where
        T: RngCore + CryptoRng,
    {
        let mut secret = self.secret.lock();

        // check if current value is still valid
        if secret.birth.elapsed() < Duration::from_secs(SECS_COOKIE_UPDATE) {
            return MAC!(&secret.value, src);
        };

        // generate new value
        rng.fill_bytes(&mut secret.value);
        secret.birth = Instant::now();
        MAC!(&secret.value, src)
    }

    fn create_cookie_reply<T>(
        &self,
        rng: &mut T,
        receiver: u32,         // receiver id of incoming message
        src: &[u8],            // source address of incoming message
        macs: &MacsFooter,     // footer of incoming message
        msg: &mut CookieReply, // resulting cookie reply
    ) where
        T: RngCore + CryptoRng,
    {
        msg.f_receiver.set(receiver);
        rng.fill_bytes(&mut msg.f_nonce);
        XSEAL!(
            &self.cookie_key,            // key
            &msg.f_nonce,                // nonce
            &macs.f_mac1,                // ad
            &self.get_set_tau(rng, src), // pt
            &mut msg.f_cookie,           // ct
            &mut msg.f_cookie_tag        // tag
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

    /// Check the mac2 field against the inner message
    ///
    /// # Arguments
    ///
    /// - inner: The inner message covered by the mac1 field
    /// - src: Source address
    /// - macs: The mac footer
    pub fn check_mac2(
        &self,
        inner: &[u8],
        src: &[u8],
        macs: &MacsFooter,
    ) -> Result<(), HandshakeError> {
        let tau = self.get_tau(src)?;
        let valid_mac2: bool = MAC!(&tau, inner, macs.f_mac1).ct_eq(&macs.f_mac2).into();
        if !valid_mac2 {
            Err(HandshakeError::InvalidMac2)
        } else {
            Ok(())
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
        let mut rng = OsRng::new().unwrap();
        let sk = StaticSecret::new(&mut rng);
        let pk = PublicKey::from(&sk);
        (Validator::new(pk), Generator::new(pk))
    }

    proptest! {
        #[test]
        fn test_cookie_reply(inner1 : Vec<u8>, inner2 : Vec<u8>, src: Vec<u8>, receiver : u32) {
            let mut msg = CookieReply::default();
            let mut rng = OsRng::new().unwrap();
            let mut macs = MacsFooter::default();
            let (validator, mut generator) = new_validator_generator();

            // generate mac1 for first message
            generator.generate(&inner1[..], &mut macs);
            assert_ne!(macs.f_mac1, [0u8; SIZE_MAC], "mac1 should be set");
            assert_eq!(macs.f_mac2, [0u8; SIZE_MAC], "mac2 should not be set");

            // check validity of mac1
            validator.check_mac1(&inner1[..], &macs).expect("mac1 of inner1 did not validate");

            // generate cookie reply in response
            validator.create_cookie_reply(&mut rng, receiver, &src[..], &macs, &mut msg);
            assert_eq!(msg.f_receiver.get(), receiver);

            // consume cookie reply
            generator.process(&msg).expect("failed to process CookieReply");

            // generate mac2 & mac2 for second message
            generator.generate(&inner2[..], &mut macs);
            assert_ne!(macs.f_mac1, [0u8; SIZE_MAC], "mac1 should be set");
            assert_ne!(macs.f_mac2, [0u8; SIZE_MAC], "mac2 should be set");

            // check validity of mac1 and mac2
            validator.check_mac1(&inner2[..], &macs).expect("mac1 of inner2 did not validate");
            validator.check_mac2(&inner2[..], &src[..], &macs).expect("mac2 of inner2 did not validate");
        }
    }
}
