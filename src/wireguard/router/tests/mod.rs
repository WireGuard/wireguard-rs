mod bench;
mod tests;

use super::message_data_len;
use super::SIZE_MESSAGE_PREFIX;
use super::{Callbacks, Device};
use super::{Key, KeyPair};

use super::super::dummy;
use super::super::tests::make_packet;

use std::time::Instant;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn pad(msg: &[u8]) -> Vec<u8> {
    let mut o = vec![0; msg.len() + SIZE_MESSAGE_PREFIX];
    o[SIZE_MESSAGE_PREFIX..SIZE_MESSAGE_PREFIX + msg.len()].copy_from_slice(msg);
    o
}

pub fn dummy_keypair(initiator: bool) -> KeyPair {
    let k1 = Key {
        key: [0x53u8; 32],
        id: 0x646e6573,
    };
    let k2 = Key {
        key: [0x52u8; 32],
        id: 0x76636572,
    };
    if initiator {
        KeyPair {
            birth: Instant::now(),
            initiator: true,
            send: k1,
            recv: k2,
        }
    } else {
        KeyPair {
            birth: Instant::now(),
            initiator: false,
            send: k2,
            recv: k1,
        }
    }
}
