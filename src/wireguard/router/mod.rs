mod anti_replay;
mod constants;
mod device;
mod inbound;
mod ip;
mod messages;
mod outbound;
mod peer;
mod pool;
mod queue;
mod route;
mod runq;
mod types;

// mod workers;

#[cfg(test)]
mod tests;

use messages::TransportHeader;
use std::mem;

use super::constants::REJECT_AFTER_MESSAGES;
use super::types::*;
use super::{tun, udp, Endpoint};

pub const SIZE_TAG: usize = 16;
pub const SIZE_MESSAGE_PREFIX: usize = mem::size_of::<TransportHeader>();
pub const CAPACITY_MESSAGE_POSTFIX: usize = SIZE_TAG;

pub const fn message_data_len(payload: usize) -> usize {
    payload + mem::size_of::<TransportHeader>() + SIZE_TAG
}

pub use device::DeviceHandle as Device;
pub use messages::TYPE_TRANSPORT;
pub use peer::PeerHandle;
pub use types::Callbacks;
