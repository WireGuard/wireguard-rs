use std::time::{SystemTime, UNIX_EPOCH};

pub type TAI64N = [u8; 12];

const TAI64_EPOCH: u64 = 0x400000000000000a;

pub const ZERO: TAI64N = [0u8; 12];

pub fn now() -> TAI64N {
    // get system time as duration
    let sysnow = SystemTime::now();
    let delta = sysnow.duration_since(UNIX_EPOCH).unwrap();

    // convert to tai64n
    let tai64_secs = delta.as_secs() + TAI64_EPOCH;
    let tai64_nano = delta.subsec_nanos();

    // serialize
    let mut res = [0u8; 12];
    res[..8].copy_from_slice(&tai64_secs.to_be_bytes()[..]);
    res[8..].copy_from_slice(&tai64_nano.to_be_bytes()[..]);
    res
}

pub fn compare(old: &TAI64N, new: &TAI64N) -> bool {
    for i in 0..12 {
        if new[i] > old[i] {
            return true;
        }
    }
    false
}
