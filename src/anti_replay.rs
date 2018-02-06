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


// This is RFC 6479.

// Power of 2.
const BITMAP_BITLEN: u64 = 2048;

const SIZE_OF_INTEGER: u64 = 32;
const BITMAP_LEN: usize = (BITMAP_BITLEN / SIZE_OF_INTEGER) as usize;
const BITMAP_INDEX_MASK: u64 = BITMAP_LEN as u64 - 1;
// REDUNDANT_BIT_SHIFTS = log2(SIZE_OF_INTEGER).
const REDUNDANT_BIT_SHIFTS: u64 = 5;
const BITMAP_LOC_MASK: u64 = SIZE_OF_INTEGER - 1;
/// Size of anti-replay window.
pub const WINDOW_SIZE: u64 = BITMAP_BITLEN - SIZE_OF_INTEGER;

pub struct AntiReplay {
    bitmap: [u32; BITMAP_LEN],
    last: u64,
}

impl Default for AntiReplay {
    fn default() -> Self {
        AntiReplay::new()
    }
}

impl AntiReplay {
    pub fn new() -> Self {
        AntiReplay {
            last: 0,
            bitmap: [0; BITMAP_LEN],
        }
    }

    /// Returns true if check is passed, i.e., not a replay or too old.
    ///
    /// Unlike RFC 6479, zero is allowed.
    pub fn check(&self, seq: u64) -> bool {
        // Larger is always good.
        if seq > self.last {
            return true;
        }

        if self.last - seq > WINDOW_SIZE {
            return false;
        }

        let bit_location = seq & BITMAP_LOC_MASK;
        let index = (seq >> REDUNDANT_BIT_SHIFTS) & BITMAP_INDEX_MASK;

        self.bitmap[index as usize] & (1 << bit_location) == 0
    }

    /// Should only be called if check returns true.
    pub fn update(&mut self, seq: u64) {
        debug_assert!(self.check(seq));

        let index = seq >> REDUNDANT_BIT_SHIFTS;

        if seq > self.last {
            let index_cur = self.last >> REDUNDANT_BIT_SHIFTS;
            let diff = index - index_cur;

            if diff >= BITMAP_LEN as u64 {
                self.bitmap = [0; BITMAP_LEN];
            } else {
                for i in 0..diff {
                    let real_index = (index_cur + i + 1) & BITMAP_INDEX_MASK;
                    self.bitmap[real_index as usize] = 0;
                }
            }

            self.last = seq;
        }

        let index = index & BITMAP_INDEX_MASK;
        let bit_location = seq & BITMAP_LOC_MASK;
        self.bitmap[index as usize] |= 1 << bit_location;
    }

    pub fn check_and_update(&mut self, seq: u64) -> bool {
        if self.check(seq) {
            self.update(seq);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anti_replay() {
        let mut ar = AntiReplay::new();

        for i in 0..20000 {
            assert!(ar.check_and_update(i));
        }

        for i in (0..20000).rev() {
            assert!(!ar.check(i));
        }

        assert!(ar.check_and_update(65536));
        for i in (65536 - WINDOW_SIZE)..65535 {
            assert!(ar.check_and_update(i));
        }
        for i in (65536 - 10 * WINDOW_SIZE)..65535 {
            assert!(!ar.check(i));
        }

        ar.check_and_update(66000);
        for i in 65537..66000 {
            assert!(ar.check_and_update(i));
        }
        for i in 65537..66000 {
            assert!(!ar.check_and_update(i));
        }

        // Test max u64.
        let next = u64::max_value();
        assert!(ar.check_and_update(next));
        assert!(!ar.check(next));
        for i in (next - WINDOW_SIZE)..next {
            assert!(ar.check_and_update(i));
        }
        for i in (next - 20 * WINDOW_SIZE)..next {
            assert!(!ar.check(i));
        }
    }

    #[bench]
    fn bench_anti_replay_sequential(b: &mut ::test::Bencher) {
        let mut ar = AntiReplay::new();
        let mut seq = 0;

        b.iter(|| {
            assert!(ar.check_and_update(seq));
            seq += 1;
        });
    }

    #[bench]
    fn bench_anti_replay_old(b: &mut ::test::Bencher) {
        let mut ar = AntiReplay::new();
        ar.check_and_update(12345);
        ar.check_and_update(11234);

        b.iter(|| {
            assert!(!ar.check_and_update(11234));
        });
    }

    #[bench]
    fn bench_anti_replay_large_skip(b: &mut ::test::Bencher) {
        let mut ar = AntiReplay::new();
        let mut seq = 0;

        b.iter(|| {
            assert!(ar.check_and_update(seq));
            seq += 30000;
        });
    }
}
