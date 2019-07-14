use hmac::{Mac, Hmac};
use blake2::{Blake2s, Digest};

use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;
use x25519_dalek::SharedSecret;

use rand::rngs::OsRng;

use generic_array::*;

use crate::types::*;
use crate::messages;

type HMACBlake2s = Hmac<Blake2s>;

/* Internal functions for processing and creating noise messages */

const SIZE_CK : usize = 32;
const SIZE_HS : usize = 32;

// C := Hash(Construction)
const INITIAL_CK : [u8; SIZE_CK] = [
    0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0,
    0x2e, 0xc3, 0x35, 0xe2, 0xa0, 0x25, 0xd2, 0xd0,
    0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72, 0x77, 0xf5,
    0x2d, 0x38, 0xd1, 0x98, 0x8b, 0x78, 0xcd, 0x36
];

// H := Hash(C || Identifier)
const INITIAL_HS : [u8; SIZE_HS] = [
    0x22, 0x11, 0xb3, 0x61, 0x08, 0x1a, 0xc5, 0x66,
    0x69, 0x12, 0x43, 0xdb, 0x45, 0x8a, 0xd5, 0x32,
    0x2d, 0x9c, 0x6c, 0x66, 0x22, 0x93, 0xe8, 0xb7,
    0x0e, 0xe1, 0x9c, 0x65, 0xba, 0x07, 0x9e, 0xf3
];

macro_rules! HASH {
    ($input1:expr) => {
        {
            let mut hsh = <Blake2s as Digest>::new();
            Digest::input(&mut hsh, $input1);
            Digest::result(hsh)
        }
    };

    ($input1:expr, $input2:expr) => {
        {
            let mut hsh = <Blake2s as Digest>::new();
            Digest::input(&mut hsh, $input1);
            Digest::input(&mut hsh, $input2);
            Digest::result(hsh)
        }
    };
}

macro_rules! HMAC {
    ($key:expr, $input:expr) => {
        {
            let mut mac = HMACBlake2s::new($key);
            mac.hash($input);
            mac.result()
        }
    };

    ($key:expr, $input1:expr, $input2:expr) => {
        HMACBlake2s::new($key).hash($input2).hash($input2).result()
    };
}

macro_rules! KDF1 {
    ($ck:expr, $input:expr) => {
        {
            let t0 = HMAC!($ck, $input);
            t0
        }
    }
}

macro_rules! KDF2 {
    ($ck:expr, $input:expr) => {

    }
}

macro_rules! KDF2 {
    ($ck:expr, $input:expr) => {

    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTIFIER : &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
    const CONSTRUCTION : &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

    #[test]
    fn precomputed_chain_key() {
        assert_eq!(INITIAL_CK[..], HASH!(CONSTRUCTION)[..]);
    }

    #[test]
    fn precomputed_hash() {
        assert_eq!(
            INITIAL_HS[..],
            HASH!(INITIAL_CK, IDENTIFIER)[..]
        );
    }
}

pub fn create_initiation(peer : &Peer, id : u32) -> Result<Vec<u8>, ()> {
    let mut rng = OsRng::new().unwrap();
    let mut msg : messages::Initiation = Default::default();

    // initialize state

    let ck = INITIAL_CK;
    let hs = INITIAL_HS;
    let hs = HASH!(&hs, peer.pk.as_bytes());

    msg.f_sender = id;

    // token : e

    let sk = StaticSecret::new(&mut rng);
    let pk = PublicKey::from(&sk);

    msg.f_ephemeral = *pk.as_bytes();

    // let ck = KDF1!(&ck, pk.as_bytes());

    // token : es

    // token : s

    // token : ss

    Ok(vec![])
}

pub fn process_initiation(peer : &Peer) -> Result<Output, ()> {
    Err(())
}

