// Copyright 2017 Sopium

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

extern crate byteorder;

use self::byteorder::{ByteOrder, LittleEndian};
use crypto::hchacha20::hchacha20;
use protocol::re_exports::{Sensitive, U8Array, ChaCha20Poly1305, Cipher};

pub fn encrypt(key: &[u8], nonce: &[u8], ad: &[u8], p: &[u8], out: &mut [u8]) {
    debug_assert_eq!(key.len(), 32);
    debug_assert_eq!(nonce.len(), 24);
    debug_assert_eq!(p.len() + 16, out.len());

    let derived_key = hchacha20(&nonce[..16], key);
    let derived_key = Sensitive::from_slice(&derived_key);

    let nonce = LittleEndian::read_u64(&nonce[16..]);

    ChaCha20Poly1305::encrypt(&derived_key, nonce, ad, p, out);
}

pub fn decrypt(key: &[u8], nonce: &[u8], ad: &[u8], c: &[u8], out: &mut [u8]) -> Result<(), ()> {
    debug_assert_eq!(key.len(), 32);
    debug_assert_eq!(nonce.len(), 24);
    debug_assert_eq!(out.len() + 16, c.len());

    let derived_key = hchacha20(&nonce[..16], key);
    let derived_key = Sensitive::from_slice(&derived_key);

    let nonce = LittleEndian::read_u64(&nonce[16..]);

    ChaCha20Poly1305::decrypt(&derived_key, nonce, ad, c, out)
}
