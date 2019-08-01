use std::time::{Duration, Instant};

use blake2::Blake2s;
use subtle::ConstantTimeEq;
use x25519_dalek::PublicKey;

use super::messages::{CookieReply, MacsFooter};
use super::types::HandshakeError;

const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";

const SIZE_COOKIE: usize = 16;
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

struct Cookie {
    value: [u8; 16],
    birth: Instant,
}

pub struct Generator {
    mac1_key: [u8; 32],
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
        unimplemented!("do the checks and decryption");
        self.cookie = Some(Cookie {
            birth: Instant::now(),
            value: reply.f_cookie,
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

pub struct Validator {
    mac1_key: [u8; 32],
}

impl Validator {
    pub fn new(pk: PublicKey) -> Validator {
        Validator {
            mac1_key: HASH!(LABEL_MAC1, pk.as_bytes()).into(),
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use x25519_dalek::StaticSecret;

    #[test]
    fn test_mac1() {
        // generate random public key
        let mut rng = OsRng::new().unwrap();
        let sk = StaticSecret::new(&mut rng);
        let pk = PublicKey::from(&sk);

        // some message
        let inner: Vec<u8> = vec![
            0x28, 0x5d, 0x9d, 0x2b, 0x40, 0x70, 0xae, 0xef, 0xbd, 0xe7, 0xc1, 0x66, 0xb4, 0x69,
            0x2a, 0x51, 0x1c, 0xb1, 0x80, 0xcc, 0x47, 0x6c, 0xec, 0xbc, 0x1f, 0x1d, 0x9c, 0x6b,
            0xfb, 0xe9, 0xc6, 0x3b, 0x64, 0x74, 0xb9, 0x41, 0xf9, 0x39, 0x2b, 0xb5, 0xd2, 0x96,
            0x51, 0xd7, 0xaa, 0x33, 0x07, 0x1f, 0x48, 0x2d, 0x7a, 0x47, 0x68, 0xd3, 0x5b, 0x63,
            0xe4, 0x03, 0x6b, 0xaa, 0xdd, 0x17, 0xfd, 0xb1, 0x24, 0x1f, 0xf3, 0x96, 0x17, 0x0b,
            0xd4, 0x9a, 0x63, 0xf3, 0x09, 0x31, 0xcb, 0xf4, 0x81, 0xae, 0xaa, 0x84, 0xf2, 0x55,
            0x31, 0x78, 0xc5, 0x3f, 0x0f, 0xa0, 0x8c, 0xa1, 0x70, 0x11, 0xcd, 0xac, 0xe0, 0x33,
            0xef, 0xfe, 0xd9, 0xa9, 0x9b, 0x3e, 0x9f, 0x65, 0x11, 0x7e, 0x30, 0x77, 0x18, 0xf2,
            0x98, 0x55, 0x10, 0xa6,
        ];

        let mut footer: MacsFooter = Default::default();

        let mut generator = Generator::new(pk);
        let validator = Validator::new(pk);

        generator.generate(&inner[..], &mut footer);
        validator.check_mac1(&inner[..], &footer).unwrap();
    }
}
