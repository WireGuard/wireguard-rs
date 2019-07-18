use std::convert::TryFrom;

// DH
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

// HASH & MAC
use hmac::{Mac, Hmac};
use blake2::{Blake2s, Digest};

// AEAD
use crypto::chacha20poly1305::ChaCha20Poly1305;
use crypto::aead::{AeadEncryptor,AeadDecryptor};

use rand::rngs::OsRng;

use crate::types::*;
use crate::peer::{State, Peer};
use crate::device::Device;
use crate::messages::{Initiation, Response};
use crate::timestamp;

type HMACBlake2s = Hmac<Blake2s>;

/* Internal functions for processing and creating noise messages */

const SIZE_CK : usize = 32;
const SIZE_HS : usize = 32;
const SIZE_NONCE : usize = 8;

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

const ZERO_NONCE : [u8; SIZE_NONCE] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
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

    ($input1:expr, $input2:expr, $input3:expr) => {
        {
            let mut hsh = <Blake2s as Digest>::new();
            Digest::input(&mut hsh, $input1);
            Digest::input(&mut hsh, $input2);
            Digest::input(&mut hsh, $input3);
            Digest::result(hsh)
        }
    };
}

macro_rules! HMAC {
    ($key:expr, $input1:expr) => {
        {
            // let mut mac = HMACBlake2s::new($key);
            let mut mac = HMACBlake2s::new_varkey($key).unwrap();
            mac.input($input1);
            mac.result().code()
        }
    };

    ($key:expr, $input1:expr, $input2:expr) => {
        {
            let mut mac = HMACBlake2s::new_varkey($key).unwrap();
            mac.input($input1);
            mac.input($input2);
            mac.result().code()
        }
    };
}

macro_rules! KDF1 {
    ($ck:expr, $input:expr) => {
        {
            let t0 = HMAC!($ck, $input);
            let t1 = HMAC!(&t0, &[0x1]);
            t1
        }
    }
}

macro_rules! KDF2 {
    ($ck:expr, $input:expr) => {
        {
            let t0 = HMAC!($ck, $input);
            let t1 = HMAC!(&t0, &[0x1]);
            let t2 = HMAC!(&t0, &t1, &[0x2]);
            (t1, t2)
        }
    }
}

macro_rules! SEAL {
    ($key:expr, $aead:expr, $pt:expr, $ct:expr, $tag:expr) => {
        {
            let mut aead = ChaCha20Poly1305::new($key, &ZERO_NONCE, $aead);
            aead.encrypt(
                $pt,
                $ct,
                $tag
            );
        }
    }
}

macro_rules! OPEN {
    ($key:expr, $aead:expr, $pt:expr, $ct:expr, $tag:expr) => {
        {
            let mut aead = ChaCha20Poly1305::new($key, &ZERO_NONCE, $aead);
            if !aead.decrypt($ct, $pt, $tag) {
                Err(HandshakeError::DecryptionFailure)
            } else {
                Ok(())
            }
        }
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

pub fn create_initiation(
    device : &Device,
    peer : &Peer,
    id : u32
) -> Result<Vec<u8>, HandshakeError> {
    let mut rng = OsRng::new().unwrap();
    let mut msg : Initiation = Default::default();

    // initialize state

    let ck = INITIAL_CK;
    let hs = INITIAL_HS;
    let hs = HASH!(&hs, peer.pk.as_bytes());

    msg.f_sender = id;

    // (E_priv, E_pub) := DH-Generate()

    let sk = StaticSecret::new(&mut rng);
    let pk = PublicKey::from(&sk);

    // C := Kdf(C, E_pub)

    let ck = KDF1!(&ck, pk.as_bytes());

    // msg.ephemeral := E_pub

    msg.f_ephemeral = *pk.as_bytes();

    // H := HASH(H, msg.ephemeral)

    let hs = HASH!(&hs, msg.f_ephemeral);

    // (C, k) := Kdf2(C, DH(E_priv, S_pub))

    let (ck, key) = KDF2!(&ck, sk.diffie_hellman(&peer.pk).as_bytes());

    // msg.static := Aead(k, 0, S_pub, H)

    SEAL!(
        &key,
        &hs,                  // ad
        device.pk.as_bytes(), // pt
        &mut msg.f_static,    // ct
        &mut msg.f_static_tag // tag
    );

    // H := Hash(H || msg.static)

    let hs = HASH!(&hs, &msg.f_static, &msg.f_static_tag);

    // (C, k) := Kdf2(C, DH(S_priv, S_pub))

    let (ck, key) = KDF2!(&ck, peer.ss.as_bytes());

    // msg.timestamp := Aead(k, 0, Timestamp(), H)

    SEAL!(
        &key,
        &hs,                     // ad
        &timestamp::now(),       // pt
        &mut msg.f_timestamp,    // ct
        &mut msg.f_timestamp_tag // tag
    );

    // H := Hash(H || msg.timestamp)

    let hs = HASH!(&hs, &msg.f_timestamp, &msg.f_timestamp_tag);

    // update state of peer

    peer.set_state(
        State::InitiationSent{
            hs : hs,
            ck : ck
        }
    );

    // return message as vector

    Ok(Initiation::into(msg))
}

pub fn process_initiation(device : &Device, msg : &[u8]) -> Result<Output, HandshakeError> {

    // parse message

    let msg = Initiation::try_from(msg)?;

    // initialize state

    let ck = INITIAL_CK;
    let hs = INITIAL_HS;
    let hs = HASH!(&hs, device.pk.as_bytes());

    // C := Kdf(C, E_pub)

    let ck = KDF1!(&ck, &msg.f_ephemeral);

    // H := HASH(H, msg.ephemeral)

    let hs = HASH!(&hs, &msg.f_ephemeral);

    // (C, k) := Kdf2(C, DH(E_priv, S_pub))

    let eph = PublicKey::from(msg.f_ephemeral);
    let (ck, key) = KDF2!(
        &ck,
        device.sk.diffie_hellman(&eph).as_bytes()
    );

    // msg.static := Aead(k, 0, S_pub, H)

    let mut pk = [0u8; 32];

    OPEN!(
        &key,
        &hs,              // ad
        &mut pk,          // pt
        &msg.f_static,    // ct
        &msg.f_static_tag // tag
    )?;

    let peer = device.lookup(&PublicKey::from(pk))?;

    // H := Hash(H || msg.static)

    let hs = HASH!(&hs, &msg.f_static, &msg.f_static_tag);

    // (C, k) := Kdf2(C, DH(S_priv, S_pub))

    let (ck, key) = KDF2!(&ck, peer.ss.as_bytes());

    // msg.timestamp := Aead(k, 0, Timestamp(), H)

    let mut ts = timestamp::zero();

    OPEN!(
        &key,
        &hs,                 // ad
        &mut ts,             // pt
        &msg.f_timestamp,    // ct
        &msg.f_timestamp_tag // tag
    )?;

    // update state of peer

    peer.set_state_timestamp(
        State::InitiationSent{
            hs : hs,
            ck : ck
        },
        &ts
    )?;

    Ok(Output(None, None))
}
