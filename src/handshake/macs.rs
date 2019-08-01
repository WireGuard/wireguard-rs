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
    pub fn process(&mut self, reply: &CookieReply) -> Option<HandshakeError> {
        self.cookie = Some(Cookie {
            birth: Instant::now(),
            value: reply.f_cookie,
        });
        None
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

    pub fn check_mac1(&self, inner: &[u8], macs: &MacsFooter) -> Result<(), HandshakeError> {
        let valid_mac1: bool = MAC!(&self.mac1_key, inner).ct_eq(&macs.f_mac1).into();
        if !valid_mac1 {
            Err(HandshakeError::InvalidMac1)
        } else {
            Ok(())
        }
    }
}
