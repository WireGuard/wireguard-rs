// via Section 6.1 of the WireGuard spec draft

#![allow(dead_code)]
use std::u64;

// transport ratcheting time limits, in seconds
pub const REKEY_ATTEMPT_TIME: u64 = 90;
pub const REKEY_AFTER_TIME: u64 = 120;
pub const REJECT_AFTER_TIME: u64 = 180;

// transport ratcheting message limits, in seconds
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - 65537;
pub const REKEY_AFTER_MESSAGES: u64 = u64::MAX - 17;

// how often to attempt rekeying
pub const REKEY_TIMEOUT: u64 = 5;

// keepalive packet timer, in seconds
pub const KEEPALIVE_TIMEOUT: u64 = 10;
