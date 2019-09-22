use std::time::Duration;
use std::u64;

pub const REKEY_AFTER_MESSAGES: u64 = u64::MAX - (1 << 16);
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 4);

pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

pub const MAX_TIMER_HANDSHAKES: usize = 18;
