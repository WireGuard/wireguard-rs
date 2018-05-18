#![allow(dead_code)]

use std::u64;
use std::time::Duration;

lazy_static! {
    pub static ref REKEY_ATTEMPT_TIME    : Duration = Duration::new(90, 0);
    pub static ref REJECT_AFTER_TIME     : Duration = Duration::new(180, 0);
    pub static ref REKEY_AFTER_TIME      : Duration = Duration::new(120, 0);
    pub static ref REKEY_AFTER_TIME_RECV : Duration = *REJECT_AFTER_TIME - *KEEPALIVE_TIMEOUT - *REKEY_TIMEOUT;
    pub static ref WIPE_AFTER_TIME       : Duration = *REJECT_AFTER_TIME * 3;

    pub static ref REKEY_TIMEOUT         : Duration = Duration::new(5, 0);
    pub static ref KEEPALIVE_TIMEOUT     : Duration = Duration::new(10, 0);
    pub static ref STALE_SESSION_TIMEOUT : Duration = *KEEPALIVE_TIMEOUT + *REKEY_TIMEOUT;

    pub static ref TIMER_RESOLUTION    : Duration = Duration::from_millis(100);
    pub static ref COOKIE_REFRESH_TIME : Duration = Duration::new(120, 0);
    pub static ref UNDER_LOAD_TIME     : Duration = Duration::new(1, 0);

    pub static ref MAX_HANDSHAKE_ATTEMPTS : u64 = REKEY_ATTEMPT_TIME.as_secs() / REKEY_TIMEOUT.as_secs() - 1;
}

// transport ratcheting message limits, in seconds
pub const REKEY_AFTER_MESSAGES  : u64 = u64::MAX - (1 << 16) - 1;
pub const REJECT_AFTER_MESSAGES : u64 = u64::MAX - (1 << 4) - 1;

pub const TRANSPORT_HEADER_SIZE : usize = 16;
pub const AEAD_TAG_SIZE         : usize = 16;
pub const TRANSPORT_OVERHEAD    : usize = TRANSPORT_HEADER_SIZE + AEAD_TAG_SIZE;
pub const MAX_SEGMENT_SIZE      : usize = (1 << 16) - 1;
pub const MAX_CONTENT_SIZE      : usize = MAX_SEGMENT_SIZE - TRANSPORT_OVERHEAD;
pub const PADDING_MULTIPLE      : usize = 16;

pub const MAX_QUEUED_HANDSHAKES : usize = 4096;
pub const UNDER_LOAD_QUEUE_SIZE : usize = MAX_QUEUED_HANDSHAKES / 8;
pub const MAX_QUEUED_PACKETS    : usize = 1024;
pub const MAX_PEERS_PER_DEVICE  : usize = 1 << 20;
