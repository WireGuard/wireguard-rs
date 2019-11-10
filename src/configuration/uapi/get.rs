use hex::FromHex;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

use super::{ConfigError, Configuration};

struct Serializer<C: Configuration> {
    config: C,
}

impl<C: Configuration> Serializer<C> {
    fn get(&self) -> Vec<String> {
        vec![]
    }
}
