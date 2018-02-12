#![allow(dead_code)]

use std::u64;

// transport ratcheting time limits, in seconds
pub const REKEY_ATTEMPT_TIME: u64 = 90;
pub const REKEY_AFTER_TIME: u64 = 120;
pub const REJECT_AFTER_TIME: u64 = 180;

// transport ratcheting message limits, in seconds
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 16) - 1;
pub const REKEY_AFTER_MESSAGES: u64 = u64::MAX - (1 << 4) - 1;

// how often to attempt rekeying
pub const REKEY_TIMEOUT: u64 = 5;

// keepalive packet timer, in seconds
pub const KEEPALIVE_TIMEOUT: u64 = 10;

pub const TRANSPORT_HEADER_SIZE: usize = 16;
pub const AEAD_TAG_SIZE: usize = 16;
pub const TRANSPORT_OVERHEAD: usize = TRANSPORT_HEADER_SIZE + AEAD_TAG_SIZE;
pub const MAX_SEGMENT_SIZE: usize = (1 << 16) - 1;
pub const MAX_CONTENT_SIZE: usize = MAX_SEGMENT_SIZE - TRANSPORT_OVERHEAD;
pub const PADDING_MULTIPLE: usize = 16;
