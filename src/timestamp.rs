pub type TAI64N = [u8; 12];

pub fn now() -> TAI64N {
    [0u8; 12] // TODO
}

pub fn compare(old : &TAI64N, new : &TAI64N) -> bool {
    for i in 0..12 {
        if new[i] > old[i] {
            return true;
        }
    }
    return false;
}
