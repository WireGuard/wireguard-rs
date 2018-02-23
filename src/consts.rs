#![allow(dead_code)]

use std::u64;
use std::time::Duration;

lazy_static! {
    pub static ref REKEY_ATTEMPT_TIME: Duration = Duration::new(90, 0);
    pub static ref REKEY_AFTER_TIME: Duration = Duration::new(121, 0);
    pub static ref REJECT_AFTER_TIME: Duration = Duration::new(180, 0);
    pub static ref REJECT_ALL_AFTER_TIME: Duration = *REJECT_AFTER_TIME * 3;
    pub static ref REKEY_TIMEOUT: Duration = Duration::new(5, 0);
    pub static ref KEEPALIVE_TIMEOUT: Duration = Duration::new(10, 0);
    pub static ref RECEIVE_REKEY_TIMEOUT: Duration = *REKEY_AFTER_TIME - *KEEPALIVE_TIMEOUT - *REKEY_TIMEOUT;
    pub static ref TIMER_RESOLUTION: Duration = Duration::from_millis(100);
    pub static ref COOKIE_REFRESH_TIME: Duration = Duration::new(120, 0);
}

// transport ratcheting message limits, in seconds
pub const REKEY_AFTER_MESSAGES: u64 = u64::MAX - (1 << 16) - 1;
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 4) - 1;


pub const TRANSPORT_HEADER_SIZE: usize = 16;
pub const AEAD_TAG_SIZE: usize = 16;
pub const TRANSPORT_OVERHEAD: usize = TRANSPORT_HEADER_SIZE + AEAD_TAG_SIZE;
pub const MAX_SEGMENT_SIZE: usize = (1 << 16) - 1;
pub const MAX_CONTENT_SIZE: usize = MAX_SEGMENT_SIZE - TRANSPORT_OVERHEAD;
pub const PADDING_MULTIPLE: usize = 16;
