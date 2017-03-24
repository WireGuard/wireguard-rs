// Copyright 2017 Guanhao Yin <sopium@mysterious.site>

// This file is part of WireGuard.rs.

// WireGuard.rs is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// WireGuard.rs is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with WireGuard.rs.  If not, see <https://www.gnu.org/licenses/>.

extern crate blake2_rfc;
extern crate sodiumoxide;

use self::blake2_rfc::blake2s::blake2s;
use self::sodiumoxide::randombytes::randombytes_into;
use self::sodiumoxide::utils::memcmp;
use crypto::xchacha20poly1305::{decrypt, encrypt};
use protocol::{Id, X25519Pubkey};

pub type Cookie = [u8; 16];

/// Calc cookie according to a secret and a bytes representation of peer address.
///
/// This is a pure function.
pub fn calc_cookie(secret: &[u8], remote_addr: &[u8]) -> Cookie {
    let mut out = [0u8; 16];
    let r = blake2s(16, secret, remote_addr);
    out.copy_from_slice(r.as_bytes());
    out
}

/// Generate cookie reply message (64 bytes).
pub fn cookie_reply(psk: Option<&[u8; 32]>,
                    pubkey: &X25519Pubkey,
                    cookie: &Cookie,
                    peer_index: Id,
                    mac1: &[u8])
                    -> [u8; 64] {
    let mut out = [0u8; 64];

    // Type and zeros.
    out[0..4].copy_from_slice(&[3, 0, 0, 0]);
    // Receiver index.
    out[4..8].copy_from_slice(peer_index.as_slice());

    {
        let (nonce, encrypted_cookie) = out[8..64].split_at_mut(24);
        randombytes_into(nonce);

        // Calc encryption key.
        let temp = blake2s(32, psk.map_or(&[], |p| p.as_ref()), pubkey.as_ref());

        // Encrypt cookie.
        encrypt(temp.as_bytes(), nonce, mac1, cookie, encrypted_cookie);
    }

    out
}

pub fn process_cookie_reply(psk: Option<&[u8; 32]>,
                            peer_pubkey: &X25519Pubkey,
                            mac1: &[u8],
                            msg: &[u8])
                            -> Result<Cookie, ()> {
    if msg.len() != 64 {
        return Err(());
    }

    if &msg[..4] != &[3, 0, 0, 0] {
        return Err(());
    }

    // msg[4..8] is sender index, skip.

    let nonce = &msg[8..32];

    let ciphertext = &msg[32..64];

    // Calc encryption key.
    let temp = blake2s(32, psk.map_or(&[], |p| p.as_ref()), peer_pubkey);

    let mut cookie = [0u8; 16];
    decrypt(temp.as_bytes(), nonce, mac1, ciphertext, &mut cookie)?;
    Ok(cookie)
}

pub fn cookie_sign(m: &mut [u8], cookie: Option<&Cookie>) {
    if cookie.is_none() {
        return;
    }
    let len = m.len();
    let (m1, m2) = m.split_at_mut(len - 16);
    let mac2 = blake2s(16, cookie.unwrap(), m1);
    m2.copy_from_slice(mac2.as_bytes());
}

pub fn cookie_verify(m: &[u8], cookie: &Cookie) -> bool {
    if m.len() < 16 {
        return false;
    }
    let (m, mac2) = m.split_at(m.len() - 16);
    let mac2_ = blake2s(16, cookie, m);
    memcmp(mac2_.as_bytes(), mac2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie() {
        let mut psk = [0u8; 32];
        randombytes_into(&mut psk);

        let mut pk = [0u8; 32];
        randombytes_into(&mut pk);

        let mut mac1 = [0u8; 16];
        randombytes_into(&mut mac1);

        let mut secret = [0u8; 32];
        randombytes_into(&mut secret);

        let cookie = calc_cookie(&secret, b"1.2.3.4");

        let reply = cookie_reply(Some(&psk), &pk, &cookie, Id::gen(), &mac1);

        let cookie1 = process_cookie_reply(Some(&psk), &pk, &mac1, &reply).unwrap();

        assert_eq!(&cookie, &cookie1);
    }
}
