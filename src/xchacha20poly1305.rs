/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

use byteorder::{ByteOrder, LittleEndian};
use chacha20_poly1305_aead;
use failure::Error;
use std::io::Cursor;
use std::num::Wrapping;

// directly ported from wireguard-go's implementation.
fn hchacha20(key: &[u8], nonce: &[u8], out: &mut [u8]) {
    let mut v00 = Wrapping(0x61707865 as u32);
    let mut v01 = Wrapping(0x3320646e as u32);
    let mut v02 = Wrapping(0x79622d32 as u32);
    let mut v03 = Wrapping(0x6b206574 as u32);

    let mut v04 = Wrapping(LittleEndian::read_u32(&key[0..]));
    let mut v05 = Wrapping(LittleEndian::read_u32(&key[4..]));
    let mut v06 = Wrapping(LittleEndian::read_u32(&key[8..]));
    let mut v07 = Wrapping(LittleEndian::read_u32(&key[12..]));
    let mut v08 = Wrapping(LittleEndian::read_u32(&key[16..]));
    let mut v09 = Wrapping(LittleEndian::read_u32(&key[20..]));
    let mut v10 = Wrapping(LittleEndian::read_u32(&key[24..]));
    let mut v11 = Wrapping(LittleEndian::read_u32(&key[28..]));
    let mut v12 = Wrapping(LittleEndian::read_u32(&nonce[0..]));
    let mut v13 = Wrapping(LittleEndian::read_u32(&nonce[4..]));
    let mut v14 = Wrapping(LittleEndian::read_u32(&nonce[8..]));
    let mut v15 = Wrapping(LittleEndian::read_u32(&nonce[12..]));

    let mut i = 0;
    while i < 20 {
        v00 += v04;
        v12 ^= v00;
        v12 = (v12 << 16) | (v12 >> 16);
        v08 += v12;
        v04 ^= v08;
        v04 = (v04 << 12) | (v04 >> 20);
        v00 += v04;
        v12 ^= v00;
        v12 = (v12 << 8) | (v12 >> 24);
        v08 += v12;
        v04 ^= v08;
        v04 = (v04 << 7) | (v04 >> 25);
        v01 += v05;
        v13 ^= v01;
        v13 = (v13 << 16) | (v13 >> 16);
        v09 += v13;
        v05 ^= v09;
        v05 = (v05 << 12) | (v05 >> 20);
        v01 += v05;
        v13 ^= v01;
        v13 = (v13 << 8) | (v13 >> 24);
        v09 += v13;
        v05 ^= v09;
        v05 = (v05 << 7) | (v05 >> 25);
        v02 += v06;
        v14 ^= v02;
        v14 = (v14 << 16) | (v14 >> 16);
        v10 += v14;
        v06 ^= v10;
        v06 = (v06 << 12) | (v06 >> 20);
        v02 += v06;
        v14 ^= v02;
        v14 = (v14 << 8) | (v14 >> 24);
        v10 += v14;
        v06 ^= v10;
        v06 = (v06 << 7) | (v06 >> 25);
        v03 += v07;
        v15 ^= v03;
        v15 = (v15 << 16) | (v15 >> 16);
        v11 += v15;
        v07 ^= v11;
        v07 = (v07 << 12) | (v07 >> 20);
        v03 += v07;
        v15 ^= v03;
        v15 = (v15 << 8) | (v15 >> 24);
        v11 += v15;
        v07 ^= v11;
        v07 = (v07 << 7) | (v07 >> 25);
        v00 += v05;
        v15 ^= v00;
        v15 = (v15 << 16) | (v15 >> 16);
        v10 += v15;
        v05 ^= v10;
        v05 = (v05 << 12) | (v05 >> 20);
        v00 += v05;
        v15 ^= v00;
        v15 = (v15 << 8) | (v15 >> 24);
        v10 += v15;
        v05 ^= v10;
        v05 = (v05 << 7) | (v05 >> 25);
        v01 += v06;
        v12 ^= v01;
        v12 = (v12 << 16) | (v12 >> 16);
        v11 += v12;
        v06 ^= v11;
        v06 = (v06 << 12) | (v06 >> 20);
        v01 += v06;
        v12 ^= v01;
        v12 = (v12 << 8) | (v12 >> 24);
        v11 += v12;
        v06 ^= v11;
        v06 = (v06 << 7) | (v06 >> 25);
        v02 += v07;
        v13 ^= v02;
        v13 = (v13 << 16) | (v13 >> 16);
        v08 += v13;
        v07 ^= v08;
        v07 = (v07 << 12) | (v07 >> 20);
        v02 += v07;
        v13 ^= v02;
        v13 = (v13 << 8) | (v13 >> 24);
        v08 += v13;
        v07 ^= v08;
        v07 = (v07 << 7) | (v07 >> 25);
        v03 += v04;
        v14 ^= v03;
        v14 = (v14 << 16) | (v14 >> 16);
        v09 += v14;
        v04 ^= v09;
        v04 = (v04 << 12) | (v04 >> 20);
        v03 += v04;
        v14 ^= v03;
        v14 = (v14 << 8) | (v14 >> 24);
        v09 += v14;
        v04 ^= v09;
        v04 = (v04 << 7) | (v04 >> 25);
        i += 2;
    }

    LittleEndian::write_u32(&mut out[0..], v00.0);
    LittleEndian::write_u32(&mut out[4..], v01.0);
    LittleEndian::write_u32(&mut out[8..], v02.0);
    LittleEndian::write_u32(&mut out[12..], v03.0);
    LittleEndian::write_u32(&mut out[16..], v12.0);
    LittleEndian::write_u32(&mut out[20..], v13.0);
    LittleEndian::write_u32(&mut out[24..], v14.0);
    LittleEndian::write_u32(&mut out[28..], v15.0);
}

pub fn encrypt(key: &[u8], nonce: &[u8], input: &[u8], aad: &[u8], output: &mut [u8]) -> Result<[u8; 16], Error> {
    ensure!(key.len() == 32, "wrong key len");
    ensure!(nonce.len() == 24, "wrong nonce len");
    ensure!(output.len() == input.len(), "output buffer not same length and input");

    let mut derived_key   = [0u8; 32];
    let mut derived_nonce = [0u8; 12];
    hchacha20(key, &nonce[..16], &mut derived_key);
    derived_nonce[4..].copy_from_slice(&nonce[16..]);

    let mut buf = Cursor::new(output);
    Ok(chacha20_poly1305_aead::encrypt(&derived_key, &derived_nonce, aad, input, &mut buf)?)
}

pub fn decrypt(key: &[u8], nonce: &[u8], input: &[u8], aad: &[u8], tag: &[u8], output: &mut [u8]) -> Result<(), Error> {
    ensure!(key.len() == 32, "wrong key len");
    ensure!(nonce.len() == 24, "wrong nonce len");
    ensure!(output.len() == input.len(), "output buffer not same length and input");

    let mut derived_key   = [0u8; 32];
    let mut derived_nonce = [0u8; 12];
    hchacha20(key, &nonce[..16], &mut derived_key);
    derived_nonce[4..].copy_from_slice(&nonce[16..]);

    let mut buf = Cursor::new(output);
    chacha20_poly1305_aead::decrypt(&derived_key, &derived_nonce, aad, input, tag, &mut buf)?;
    Ok(())
}

#[test]
fn sanity() {
    let     key   = &[1u8; 32];
    let     nonce = &[2u8; 24];
    let     aad   = &[3u8; 16];
    let     input = b"Readings fluxuated momentarily. It appeared to be a ship, but then it vanished.";
    let mut enc   = vec![0u8; input.len()];
    let mut dec   = vec![0u8; input.len()];

    let tag = encrypt(key, nonce, input, aad, &mut enc).unwrap();

    decrypt(key, nonce, &enc, aad, &tag, &mut dec).unwrap();

    assert!(&input[..] == &dec[..]);
}

#[test]
fn wireguard_go_vectors() {
    use hex::{encode, decode};
    struct XChaCha20Test {
        nonce: &'static str,
        key: &'static str,
        pt: &'static str,
        ct: &'static str,
    };
    let tests = [
        XChaCha20Test {
            nonce: "000000000000000000000000000000000000000000000000",
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            pt: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            ct: "789e9689e5208d7fd9e1f3c5b5341f48ef18a13e418998addadd97a3693a987f8e82ecd5c1433bfed1af49750c0f1ff29c4174a05b119aa3a9e8333812e0c0feb1299c5949d895ee01dbf50f8395dd84",
        },
        XChaCha20Test {
            nonce: "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
            key:   "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
            pt:    "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
            ct:    "e1a046aa7f71e2af8b80b6408b2fd8d3a350278cde79c94d9efaa475e1339b3dd490127b",
        },
        XChaCha20Test {
            nonce: "d9a8213e8a697508805c2c171ad54487ead9e3e02d82d5bc",
            key:   "979196dbd78526f2f584f7534db3f5824d8ccfa858ca7e09bdd3656ecd36033c",
            pt:    "43cc6d624e451bbed952c3e071dc6c03392ce11eb14316a94b2fdc98b22fedea",
            ct:    "53c1e8bef2dbb8f2505ec010a7afe21d5a8e6dd8f987e4ea1a2ed5dfbc844ea400db34496fd2153526c6e87c36694200",
        }
    ];

    for test in tests.iter() {
        let nonce = decode(test.nonce).unwrap();
        let key = decode(test.key).unwrap();
        let pt = decode(test.pt).unwrap();
        let ct = decode(test.ct).unwrap();

        let mut buf = vec![0u8; pt.len()];
        let tag = encrypt(&key, &nonce, &pt, &[], &mut buf[..]).unwrap();

        println!("\nthr {}", test.ct);
        println!("our {}", encode(&buf));
        assert!(&[&buf[..], &tag[..]].concat() == &ct);

        decrypt(&key, &nonce, &ct[..pt.len()], &[], &tag, &mut buf[..]).unwrap();
        println!("\nthr {}", test.pt);
        println!("our {}", encode(&buf));
        assert!(&buf == &pt);
    }
}

