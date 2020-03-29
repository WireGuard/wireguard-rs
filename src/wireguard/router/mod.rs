mod anti_replay;
mod constants;
mod device;
mod ip;
mod messages;
mod peer;
mod route;
mod types;

mod queue;
mod receive;
mod send;
mod worker;

#[cfg(test)]
mod tests;

use messages::TransportHeader;

use super::constants::REJECT_AFTER_MESSAGES;
use super::queue::ParallelQueue;
use super::types::*;

use core::mem;

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
