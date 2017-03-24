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


// Ported from the libsodium.

extern crate byteorder;

use self::byteorder::{ByteOrder, LittleEndian};

macro_rules! rotate {
    ($v:expr, $c:expr) => (($v << $c) | ($v >> (32 - $c)))
}

macro_rules! quarter_round {
    ($a:ident, $b:ident, $c:ident, $d:ident) => {
    $a = $a.wrapping_add($b);
    $d = rotate!($d ^ $a, 16);
    $c = $c.wrapping_add($d);
    $b = rotate!($b ^ $c, 12);
    $a = $a.wrapping_add($b);
    $d = rotate!($d ^ $a, 8);
    $c = $c.wrapping_add($d);
    $b = rotate!($b ^ $c, 7);
    }
}

/// The `hchacha20` primitive, same as libsodium.
pub fn hchacha20(input: &[u8], key: &[u8]) -> [u8; 32] {
    // It's a bit difficult to work with &[u8; 16], &[u8; 32], etc. So just use slices, and assert
    // their lengths.
    assert_eq!(input.len(), 16);
    assert_eq!(key.len(), 32);

    let mut x0 = 0x61707865u32;
    let mut x1 = 0x3320646eu32;
    let mut x2 = 0x79622d32u32;
    let mut x3 = 0x6b206574u32;
    let mut x4 = LittleEndian::read_u32(&key[0..4]);
    let mut x5 = LittleEndian::read_u32(&key[4..8]);
    let mut x6 = LittleEndian::read_u32(&key[8..12]);
    let mut x7 = LittleEndian::read_u32(&key[12..16]);
    let mut x8 = LittleEndian::read_u32(&key[16..20]);
    let mut x9 = LittleEndian::read_u32(&key[20..24]);
    let mut x10 = LittleEndian::read_u32(&key[24..28]);
    let mut x11 = LittleEndian::read_u32(&key[28..32]);
    let mut x12 = LittleEndian::read_u32(&input[0..4]);
    let mut x13 = LittleEndian::read_u32(&input[4..8]);
    let mut x14 = LittleEndian::read_u32(&input[8..12]);
    let mut x15 = LittleEndian::read_u32(&input[12..16]);

    for _ in 0..10 {
        quarter_round!(x0, x4, x8, x12);
        quarter_round!(x1, x5, x9, x13);
        quarter_round!(x2, x6, x10, x14);
        quarter_round!(x3, x7, x11, x15);
        quarter_round!(x0, x5, x10, x15);
        quarter_round!(x1, x6, x11, x12);
        quarter_round!(x2, x7, x8, x13);
        quarter_round!(x3, x4, x9, x14);
    }

    let mut out = [0u8; 32];

    LittleEndian::write_u32(&mut out[0..4], x0);
    LittleEndian::write_u32(&mut out[4..8], x1);
    LittleEndian::write_u32(&mut out[8..12], x2);
    LittleEndian::write_u32(&mut out[12..16], x3);
    LittleEndian::write_u32(&mut out[16..20], x12);
    LittleEndian::write_u32(&mut out[20..24], x13);
    LittleEndian::write_u32(&mut out[24..28], x14);
    LittleEndian::write_u32(&mut out[28..32], x15);

    out
}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;

    use self::rustc_serialize::hex::FromHex;

    #[test]
    fn hchacha20_vectors() {
        // From libsodium.
        // [[key, in, out]]
        let vec = [["24f11cce8a1b3d61e441561a696c1c1b7e173d084fd4812425435a8896a013dc",
                    "d9660c5900ae19ddad28d6e06e45fe5e",
                    "5966b3eec3bff1189f831f06afe4d4e3be97fa9235ec8c20d08acfbbb4e851e3"],
                   ["80a5f6272031e18bb9bcd84f3385da65e7731b7039f13f5e3d475364cd4d42f7",
                    "c0eccc384b44c88e92c57eb2d5ca4dfa",
                    "6ed11741f724009a640a44fce7320954c46e18e0d7ae063bdbc8d7cf372709df"],
                   ["cb1fc686c0eec11a89438b6f4013bf110e7171dace3297f3a657a309b3199629",
                    "fcd49b93e5f8f299227e64d40dc864a3",
                    "84b7e96937a1a0a406bb7162eeaad34308d49de60fd2f7ec9dc6a79cbab2ca34"],
                   ["6640f4d80af5496ca1bc2cfff1fefbe99638dbceaabd7d0ade118999d45f053d",
                    "31f59ceeeafdbfe8cae7914caeba90d6",
                    "9af4697d2f5574a44834a2c2ae1a0505af9f5d869dbe381a994a18eb374c36a0"],
                   ["0693ff36d971225a44ac92c092c60b399e672e4cc5aafd5e31426f123787ac27",
                    "3a6293da061da405db45be1731d5fc4d",
                    "f87b38609142c01095bfc425573bb3c698f9ae866b7e4216840b9c4caf3b0865"],
                   ["809539bd2639a23bf83578700f055f313561c7785a4a19fc9114086915eee551",
                    "780c65d6a3318e479c02141d3f0b3918",
                    "902ea8ce4680c09395ce71874d242f84274243a156938aaa2dd37ac5be382b42"],
                   ["1a170ddf25a4fd69b648926e6d794e73408805835c64b2c70efddd8cd1c56ce0",
                    "05dbee10de87eb0c5acb2b66ebbe67d3",
                    "a4e20b634c77d7db908d387b48ec2b370059db916e8ea7716dc07238532d5981"],
                   ["3b354e4bb69b5b4a1126f509e84cad49f18c9f5f29f0be0c821316a6986e15a6",
                    "d8a89af02f4b8b2901d8321796388b6c",
                    "9816cb1a5b61993735a4b161b51ed2265b696e7ded5309c229a5a99f53534fbc"],
                   ["4b9a818892e15a530db50dd2832e95ee192e5ed6afffb408bd624a0c4e12a081",
                    "a9079c551de70501be0286d1bc78b045",
                    "ebc5224cf41ea97473683b6c2f38a084bf6e1feaaeff62676db59d5b719d999b"],
                   ["c49758f00003714c38f1d4972bde57ee8271f543b91e07ebce56b554eb7fa6a7",
                    "31f0204e10cf4f2035f9e62bb5ba7303",
                    "0dd8cc400f702d2c06ed920be52048a287076b86480ae273c6d568a2e9e7518c"]];

        for v in &vec {
            let key = v[0].from_hex().unwrap();
            let input = v[1].from_hex().unwrap();
            let expected = v[2].from_hex().unwrap();

            let out = super::hchacha20(input.as_slice(), key.as_slice());
            assert_eq!(&expected, &out);
        }
    }
}
