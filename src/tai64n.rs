use byteorder::{ByteOrder, BigEndian};
use std::ops::Deref;
use std::time::{SystemTime, UNIX_EPOCH};

const TAI64N_BASE: i64 = 4611686018427387914;

#[derive(PartialEq, PartialOrd)]
pub struct TAI64N {
    tai64n: [u8; 12]
}

impl TAI64N {
    pub fn now() -> TAI64N {
        let mut tai64n = [0u8; 12];
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        BigEndian::write_i64(&mut tai64n[0..], TAI64N_BASE + now.as_secs() as i64);
        BigEndian::write_i32(&mut tai64n[8..], (now.subsec_nanos() as i32));

        TAI64N { tai64n }
    }
}

impl Deref for TAI64N {
    type Target = [u8; 12];

    fn deref(&self) -> &[u8; 12] {
        &self.tai64n
    }
}

impl From<[u8; 12]> for TAI64N {
    fn from(tai64n: [u8; 12]) -> Self {
        TAI64N { tai64n }
    }
}
