use x25519_dalek;
use rand::RngCore;
use rand::CryptoRng;

use std::fmt;
use std::cmp::Eq;
use std::ops::Deref;
use std::str::FromStr;
use std::hash::{Hash, Hasher};
use std::convert::AsRef;

#[derive(Copy, Clone)]
pub struct PresharedSecret([u8; 32]);

impl FromStr for PresharedSecret {
    type Err = (); // TODO: better error type

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match hex::decode(s) {
            Ok(v) =>
                if v.len() == 32 {
                    let mut psk = [0u8; 32];
                    psk.copy_from_slice(&v);
                    Ok(PresharedSecret(psk))
                } else {
                    Err(())
                }
            ,
            Err(_) => Err(())
        }
    }
}

impl Default for PresharedSecret {
    fn default() -> Self {
        Self([0u8; 32])
    }
}

impl AsRef<[u8]> for PresharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl PresharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// required traits for PublicKey

#[derive(Copy, Clone)]
pub struct PublicKey(x25519_dalek::PublicKey);

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for PublicKey {}

impl Deref for PublicKey {
    type Target = x25519_dalek::PublicKey;
    fn deref(&self) -> &x25519_dalek::PublicKey {
        return &self.0
    }
}

impl FromStr for PublicKey {
    type Err = (); // TODO: better error type

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match hex::decode(s) {
            Ok(v) =>
                if v.len() == 32 {
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(&v);
                    Ok(PublicKey(x25519_dalek::PublicKey::from(pk)))
                } else {
                    Err(())
                }
            ,
            Err(_) => Err(())
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.as_bytes()))
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(pk : [u8; 32]) -> Self {
        PublicKey(x25519_dalek::PublicKey::from(pk))
    }
}

impl From<&StaticSecret> for PublicKey {
    fn from(sk : &StaticSecret) -> Self {
        PublicKey(x25519_dalek::PublicKey::from(&sk.0))
    }
}

// required traits for StaticSecret

#[derive(Clone)]
pub struct StaticSecret(x25519_dalek::StaticSecret);

impl Deref for StaticSecret {
    type Target = x25519_dalek::StaticSecret;
    fn deref(&self) -> &Self::Target {
        return &self.0
    }
}

impl StaticSecret {
    pub fn new<T>(csprng: &mut T) -> Self where T: RngCore + CryptoRng {
        StaticSecret(x25519_dalek::StaticSecret::new(csprng))
    }
}

impl From<[u8; 32]> for StaticSecret {
    fn from(v : [u8; 32]) -> Self {
        StaticSecret(x25519_dalek::StaticSecret::from(v))
    }
}

impl fmt::Debug for StaticSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StaticSecret({})", hex::encode(self.to_bytes()))
    }
}

impl FromStr for StaticSecret {
    type Err = (); // TODO: better error type

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match hex::decode(s) {
            Ok(v) =>
                if v.len() == 32 {
                    let mut sk = [0u8; 32];
                    sk.copy_from_slice(&v);
                    Ok(StaticSecret(x25519_dalek::StaticSecret::from(sk)))
                } else {
                    Err(())
                }
            ,
            Err(_) => Err(())
        }
    }
}

// required traits for SharedSecret

pub type SharedSecret = x25519_dalek::SharedSecret;
