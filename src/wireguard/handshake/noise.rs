// DH
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

// HASH & MAC
use blake2::Blake2s;
use hmac::Hmac;

// AEAD
use aead::{Aead, NewAead, Payload};
use chacha20poly1305::ChaCha20Poly1305;

use rand::{CryptoRng, RngCore};

use log::debug;

use generic_array::typenum::*;
use generic_array::*;

use clear_on_drop::clear::Clear;
use clear_on_drop::clear_stack_on_return;

use subtle::ConstantTimeEq;

use super::device::{Device, KeyState};
use super::messages::{NoiseInitiation, NoiseResponse};
use super::messages::{TYPE_INITIATION, TYPE_RESPONSE};
use super::peer::{Peer, State};
use super::timestamp;
use super::types::*;

use super::super::types::{Key, KeyPair};

use std::time::Instant;

// HMAC hasher (generic construction)

type HMACBlake2s = Hmac<Blake2s>;

// convenient alias to pass state temporarily into device.rs and back

type TemporaryState = (u32, PublicKey, GenericArray<u8, U32>, GenericArray<u8, U32>);

const SIZE_CK: usize = 32;
const SIZE_HS: usize = 32;
const SIZE_NONCE: usize = 8;
const SIZE_TAG: usize = 16;

// number of pages to clear after sensitive call
const CLEAR_PAGES: usize = 1;

// C := Hash(Construction)
const INITIAL_CK: [u8; SIZE_CK] = [
    0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0, 0x2e, 0xc3, 0x35, 0xe2, 0xa0, 0x25, 0xd2, 0xd0,
    0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72, 0x77, 0xf5, 0x2d, 0x38, 0xd1, 0x98, 0x8b, 0x78, 0xcd, 0x36,
];

// H := Hash(C || Identifier)
const INITIAL_HS: [u8; SIZE_HS] = [
    0x22, 0x11, 0xb3, 0x61, 0x08, 0x1a, 0xc5, 0x66, 0x69, 0x12, 0x43, 0xdb, 0x45, 0x8a, 0xd5, 0x32,
    0x2d, 0x9c, 0x6c, 0x66, 0x22, 0x93, 0xe8, 0xb7, 0x0e, 0xe1, 0x9c, 0x65, 0xba, 0x07, 0x9e, 0xf3,
];

const ZERO_NONCE: [u8; 12] = [0u8; 12];

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

macro_rules! HMAC {
    ($key:expr, $($input:expr),*) => {{
        use hmac::Mac;
        let mut mac = HMACBlake2s::new_varkey($key).unwrap();
        $(
            mac.input($input);
        )*
        mac.result().code()
    }};
}

macro_rules! KDF1 {
    ($ck:expr, $input:expr) => {{
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        t0.clear();
        t1
    }};
}

macro_rules! KDF2 {
    ($ck:expr, $input:expr) => {{
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        let t2 = HMAC!(&t0, &t1, &[0x2]);
        t0.clear();
        (t1, t2)
    }};
}

macro_rules! KDF3 {
    ($ck:expr, $input:expr) => {{
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        let t2 = HMAC!(&t0, &t1, &[0x2]);
        let t3 = HMAC!(&t0, &t2, &[0x3]);
        t0.clear();
        (t1, t2, t3)
    }};
}

macro_rules! SEAL {
    ($key:expr, $ad:expr, $pt:expr, $ct:expr) => {
        ChaCha20Poly1305::new(*GenericArray::from_slice($key))
            .encrypt(&ZERO_NONCE.into(), Payload { msg: $pt, aad: $ad })
            .map(|ct| $ct.copy_from_slice(&ct))
            .unwrap()
    };
}

macro_rules! OPEN {
    ($key:expr, $ad:expr, $pt:expr, $ct:expr) => {
        ChaCha20Poly1305::new(*GenericArray::from_slice($key))
            .decrypt(&ZERO_NONCE.into(), Payload { msg: $ct, aad: $ad })
            .map_err(|_| HandshakeError::DecryptionFailure)
            .map(|pt| $pt.copy_from_slice(&pt))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
    const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

    /* Sanity check precomputed initial chain key
     */
    #[test]
    fn precomputed_chain_key() {
        assert_eq!(INITIAL_CK[..], HASH!(CONSTRUCTION)[..]);
    }

    /* Sanity check precomputed initial hash transcript
     */
    #[test]
    fn precomputed_hash() {
        assert_eq!(INITIAL_HS[..], HASH!(INITIAL_CK, IDENTIFIER)[..]);
    }

    /* Sanity check the HKDF macro
     *
     * Test vectors generated using WireGuard-Go
     */
    #[test]
    fn hkdf() {
        let tests: Vec<(Vec<u8>, Vec<u8>, [u8; 32], [u8; 32], [u8; 32])> = vec![
            (
                vec![],
                vec![],
                [
                    0x83, 0x87, 0xb4, 0x6b, 0xf4, 0x3e, 0xcc, 0xfc, 0xf3, 0x49, 0x55, 0x2a, 0x09,
                    0x5d, 0x83, 0x15, 0xc4, 0x05, 0x5b, 0xeb, 0x90, 0x20, 0x8f, 0xb1, 0xbe, 0x23,
                    0xb8, 0x94, 0xbc, 0x2e, 0xd5, 0xd0,
                ],
                [
                    0x58, 0xa0, 0xe5, 0xf6, 0xfa, 0xef, 0xcc, 0xf4, 0x80, 0x7b, 0xff, 0x1f, 0x05,
                    0xfa, 0x8a, 0x92, 0x17, 0x94, 0x57, 0x62, 0x04, 0x0b, 0xce, 0xc2, 0xf4, 0xb4,
                    0xa6, 0x2b, 0xdf, 0xe0, 0xe8, 0x6e,
                ],
                [
                    0x0c, 0xe6, 0xea, 0x98, 0xec, 0x54, 0x8f, 0x8e, 0x28, 0x1e, 0x93, 0xe3, 0x2d,
                    0xb6, 0x56, 0x21, 0xc4, 0x5e, 0xb1, 0x8d, 0xc6, 0xf0, 0xa7, 0xad, 0x94, 0x17,
                    0x86, 0x10, 0xa2, 0xf7, 0x33, 0x8e,
                ],
            ),
            (
                vec![0xde, 0xad, 0xbe, 0xef],
                vec![],
                [
                    0x55, 0x32, 0x9d, 0xc8, 0x0e, 0x69, 0x0f, 0xd8, 0x6b, 0xd9, 0x66, 0x1f, 0x08,
                    0x51, 0xc9, 0xb3, 0x68, 0x6d, 0xf2, 0xb1, 0xfd, 0xa0, 0x34, 0x7b, 0xc3, 0xd2,
                    0x79, 0x58, 0x25, 0x4b, 0x32, 0xc6,
                ],
                [
                    0x8d, 0xfc, 0x6d, 0x33, 0xa8, 0x11, 0x8f, 0xfe, 0x40, 0x8b, 0x31, 0xdd, 0xac,
                    0x25, 0xf7, 0x2a, 0xee, 0x91, 0x15, 0xa4, 0x5b, 0x69, 0xba, 0x17, 0x6a, 0xd0,
                    0x12, 0xb2, 0x43, 0x83, 0x4f, 0xee,
                ],
                [
                    0xd6, 0x9e, 0x85, 0x2a, 0x28, 0x96, 0x56, 0x9e, 0xa5, 0x4a, 0x67, 0x96, 0x9a,
                    0xa1, 0x80, 0x02, 0x87, 0x92, 0x1d, 0xac, 0x53, 0xce, 0x6d, 0xb4, 0xb4, 0xe1,
                    0x21, 0x92, 0xf2, 0x63, 0xc4, 0xc4,
                ],
            ),
        ];

        for (key, input, t0, t1, t2) in &tests {
            let tt0 = KDF1!(key, input);
            debug_assert_eq!(tt0[..], t0[..]);

            let (tt0, tt1) = KDF2!(key, input);
            debug_assert_eq!(tt0[..], t0[..]);
            debug_assert_eq!(tt1[..], t1[..]);

            let (tt0, tt1, tt2) = KDF3!(key, input);
            debug_assert_eq!(tt0[..], t0[..]);
            debug_assert_eq!(tt1[..], t1[..]);
            debug_assert_eq!(tt2[..], t2[..]);
        }
    }
}

pub fn create_initiation<R: RngCore + CryptoRng>(
    rng: &mut R,
    keyst: &KeyState,
    peer: &Peer,
    sender: u32,
    msg: &mut NoiseInitiation,
) -> Result<(), HandshakeError> {
    debug!("create initation");
    clear_stack_on_return(CLEAR_PAGES, || {
        // initialize state

        let ck = INITIAL_CK;
        let hs = INITIAL_HS;
        let hs = HASH!(&hs, peer.pk.as_bytes());

        msg.f_type.set(TYPE_INITIATION as u32);
        msg.f_sender.set(sender);

        // (E_priv, E_pub) := DH-Generate()

        let eph_sk = StaticSecret::new(rng);
        let eph_pk = PublicKey::from(&eph_sk);

        // C := Kdf(C, E_pub)

        let ck = KDF1!(&ck, eph_pk.as_bytes());

        // msg.ephemeral := E_pub

        msg.f_ephemeral = *eph_pk.as_bytes();

        // H := HASH(H, msg.ephemeral)

        let hs = HASH!(&hs, msg.f_ephemeral);

        // (C, k) := Kdf2(C, DH(E_priv, S_pub))

        let (ck, key) = KDF2!(&ck, eph_sk.diffie_hellman(&peer.pk).as_bytes());

        // msg.static := Aead(k, 0, S_pub, H)

        SEAL!(
            &key,
            &hs,                 // ad
            keyst.pk.as_bytes(), // pt
            &mut msg.f_static    // ct || tag
        );

        // H := Hash(H || msg.static)

        let hs = HASH!(&hs, &msg.f_static[..]);

        // (C, k) := Kdf2(C, DH(S_priv, S_pub))

        let (ck, key) = KDF2!(&ck, &peer.ss);

        // msg.timestamp := Aead(k, 0, Timestamp(), H)

        SEAL!(
            &key,
            &hs,                  // ad
            &timestamp::now(),    // pt
            &mut msg.f_timestamp  // ct || tag
        );

        // H := Hash(H || msg.timestamp)

        let hs = HASH!(&hs, &msg.f_timestamp);

        // update state of peer

        *peer.state.lock() = State::InitiationSent {
            hs,
            ck,
            eph_sk,
            sender,
        };

        Ok(())
    })
}

pub fn consume_initiation<'a>(
    device: &'a Device,
    keyst: &KeyState,
    msg: &NoiseInitiation,
) -> Result<(&'a Peer, TemporaryState), HandshakeError> {
    debug!("consume initation");
    clear_stack_on_return(CLEAR_PAGES, || {
        // initialize new state

        let ck = INITIAL_CK;
        let hs = INITIAL_HS;
        let hs = HASH!(&hs, keyst.pk.as_bytes());

        // C := Kdf(C, E_pub)

        let ck = KDF1!(&ck, &msg.f_ephemeral);

        // H := HASH(H, msg.ephemeral)

        let hs = HASH!(&hs, &msg.f_ephemeral);

        // (C, k) := Kdf2(C, DH(E_priv, S_pub))

        let eph_r_pk = PublicKey::from(msg.f_ephemeral);
        let (ck, key) = KDF2!(&ck, keyst.sk.diffie_hellman(&eph_r_pk).as_bytes());

        // msg.static := Aead(k, 0, S_pub, H)

        let mut pk = [0u8; 32];

        OPEN!(
            &key,
            &hs,           // ad
            &mut pk,       // pt
            &msg.f_static  // ct || tag
        )?;

        let peer = device.lookup_pk(&PublicKey::from(pk))?;

        // reset initiation state

        *peer.state.lock() = State::Reset;

        // H := Hash(H || msg.static)

        let hs = HASH!(&hs, &msg.f_static[..]);

        // (C, k) := Kdf2(C, DH(S_priv, S_pub))

        let (ck, key) = KDF2!(&ck, &peer.ss);

        // msg.timestamp := Aead(k, 0, Timestamp(), H)

        let mut ts = timestamp::ZERO;

        OPEN!(
            &key,
            &hs,              // ad
            &mut ts,          // pt
            &msg.f_timestamp  // ct || tag
        )?;

        // check and update timestamp

        peer.check_replay_flood(device, &ts)?;

        // H := Hash(H || msg.timestamp)

        let hs = HASH!(&hs, &msg.f_timestamp);

        // return state (to create response)

        Ok((peer, (msg.f_sender.get(), eph_r_pk, hs, ck)))
    })
}

pub fn create_response<R: RngCore + CryptoRng>(
    rng: &mut R,
    peer: &Peer,
    sender: u32,             // sending identifier
    state: TemporaryState,   // state from "consume_initiation"
    msg: &mut NoiseResponse, // resulting response
) -> Result<KeyPair, HandshakeError> {
    debug!("create response");
    clear_stack_on_return(CLEAR_PAGES, || {
        // unpack state

        let (receiver, eph_r_pk, hs, ck) = state;

        msg.f_type.set(TYPE_RESPONSE as u32);
        msg.f_sender.set(sender);
        msg.f_receiver.set(receiver);

        // (E_priv, E_pub) := DH-Generate()

        let eph_sk = StaticSecret::new(rng);
        let eph_pk = PublicKey::from(&eph_sk);

        // C := Kdf1(C, E_pub)

        let ck = KDF1!(&ck, eph_pk.as_bytes());

        // msg.ephemeral := E_pub

        msg.f_ephemeral = *eph_pk.as_bytes();

        // H := Hash(H || msg.ephemeral)

        let hs = HASH!(&hs, &msg.f_ephemeral);

        // C := Kdf1(C, DH(E_priv, E_pub))

        let ck = KDF1!(&ck, eph_sk.diffie_hellman(&eph_r_pk).as_bytes());

        // C := Kdf1(C, DH(E_priv, S_pub))

        let ck = KDF1!(&ck, eph_sk.diffie_hellman(&peer.pk).as_bytes());

        // (C, tau, k) := Kdf3(C, Q)

        let (ck, tau, key) = KDF3!(&ck, &peer.psk);

        // H := Hash(H || tau)

        let hs = HASH!(&hs, tau);

        // msg.empty := Aead(k, 0, [], H)

        SEAL!(
            &key,
            &hs,              // ad
            &[],              // pt
            &mut msg.f_empty  // \epsilon || tag
        );

        // Not strictly needed
        // let hs = HASH!(&hs, &msg.f_empty_tag);

        // derive key-pair

        let (key_recv, key_send) = KDF2!(&ck, &[]);

        // return unconfirmed key-pair

        Ok(KeyPair {
            birth: Instant::now(),
            initiator: false,
            send: Key {
                id: sender,
                key: key_send.into(),
            },
            recv: Key {
                id: receiver,
                key: key_recv.into(),
            },
        })
    })
}

/* The state lock is released while processing the message to
 * allow concurrent processing of potential responses to the initiation,
 * in order to better mitigate DoS from malformed response messages.
 */
pub fn consume_response(
    device: &Device,
    keyst: &KeyState,
    msg: &NoiseResponse,
) -> Result<Output, HandshakeError> {
    debug!("consume response");
    clear_stack_on_return(CLEAR_PAGES, || {
        // retrieve peer and copy initiation state
        let peer = device.lookup_id(msg.f_receiver.get())?;

        let (hs, ck, sender, eph_sk) = match *peer.state.lock() {
            State::InitiationSent {
                hs,
                ck,
                sender,
                ref eph_sk,
            } => Ok((hs, ck, sender, StaticSecret::from(eph_sk.to_bytes()))),
            _ => Err(HandshakeError::InvalidState),
        }?;

        // C := Kdf1(C, E_pub)

        let ck = KDF1!(&ck, &msg.f_ephemeral);

        // H := Hash(H || msg.ephemeral)

        let hs = HASH!(&hs, &msg.f_ephemeral);

        // C := Kdf1(C, DH(E_priv, E_pub))

        let eph_r_pk = PublicKey::from(msg.f_ephemeral);
        let ck = KDF1!(&ck, eph_sk.diffie_hellman(&eph_r_pk).as_bytes());

        // C := Kdf1(C, DH(E_priv, S_pub))

        let ck = KDF1!(&ck, keyst.sk.diffie_hellman(&eph_r_pk).as_bytes());

        // (C, tau, k) := Kdf3(C, Q)

        let (ck, tau, key) = KDF3!(&ck, &peer.psk);

        // H := Hash(H || tau)

        let hs = HASH!(&hs, tau);

        // msg.empty := Aead(k, 0, [], H)

        OPEN!(
            &key,
            &hs,          // ad
            &mut [],      // pt
            &msg.f_empty  // \epsilon || tag
        )?;

        // derive key-pair

        let birth = Instant::now();
        let (key_send, key_recv) = KDF2!(&ck, &[]);

        // check for new initiation sent while lock released

        let mut state = peer.state.lock();
        let update = match *state {
            State::InitiationSent {
                eph_sk: ref old, ..
            } => old.to_bytes().ct_eq(&eph_sk.to_bytes()).into(),
            _ => false,
        };

        if update {
            // null the initiation state
            // (to avoid replay of this response message)
            *state = State::Reset;

            // return confirmed key-pair
            Ok((
                Some(peer.pk),
                None,
                Some(KeyPair {
                    birth,
                    initiator: true,
                    send: Key {
                        id: sender,
                        key: key_send.into(),
                    },
                    recv: Key {
                        id: msg.f_sender.get(),
                        key: key_recv.into(),
                    },
                }),
            ))
        } else {
            Err(HandshakeError::InvalidState)
        }
    })
}
