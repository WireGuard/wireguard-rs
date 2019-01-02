/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

use byteorder::{ByteOrder, BigEndian};
use std::ops::Deref;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TAI64N_BASE: i64 = 4611686018427387914;

#[derive(PartialEq, PartialOrd)]
pub struct Tai64n {
    tai64n: [u8; 12]
}

impl Tai64n {
    pub fn now() -> Tai64n {
        let mut tai64n = [0u8; 12];
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        BigEndian::write_i64(&mut tai64n[0..], TAI64N_BASE + now.as_secs() as i64);
        BigEndian::write_i32(&mut tai64n[8..], now.subsec_nanos() as i32);

        Tai64n { tai64n }
    }
}

impl Deref for Tai64n {
    type Target = [u8; 12];

    fn deref(&self) -> &[u8; 12] {
        &self.tai64n
    }
}

impl From<[u8; 12]> for Tai64n {
    fn from(tai64n: [u8; 12]) -> Self {
        Tai64n { tai64n }
    }
}

// TODO I don't like this.
lazy_static! {
    pub static ref FOREVER:     Duration = Duration::from_secs(0xffffffff);
    pub static ref FOREVER_AGO: Instant  = Instant::now() - Duration::from_secs(0xffffffff);
}

pub struct Timestamp(Option<Instant>);

impl Default for Timestamp {
    fn default() -> Self {
        Timestamp(None)
    }
}

impl Deref for Timestamp {
    type Target = Instant;

    fn deref(&self) -> &Self::Target {
        match self.0 {
            Some(ref time) => time,
            None           => &*FOREVER_AGO,
        }
    }
}

impl Timestamp {
    pub fn now() -> Self {
        Timestamp(Some(Instant::now()))
    }

    pub fn unset() -> Self {
        Timestamp(None)
    }

    pub fn is_set(&self) -> bool {
        self.0.is_some()
    }

    pub fn elapsed(&self) -> Duration {
        match self.0 {
            Some(ref time) => Instant::now().duration_since(*time),
            None           => *FOREVER,
        }
    }
}
