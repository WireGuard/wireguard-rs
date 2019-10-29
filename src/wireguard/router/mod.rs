mod anti_replay;
mod constants;
mod device;
mod ip;
mod messages;
mod peer;
mod route;
mod types;
mod workers;

#[cfg(test)]
mod tests;

use messages::TransportHeader;
use std::mem;

pub const SIZE_MESSAGE_PREFIX: usize = mem::size_of::<TransportHeader>();
pub const CAPACITY_MESSAGE_POSTFIX: usize = workers::SIZE_TAG;

pub const fn message_data_len(payload: usize) -> usize {
    payload + mem::size_of::<TransportHeader>() + workers::SIZE_TAG
}

pub use device::Device;
pub use messages::TYPE_TRANSPORT;
pub use peer::Peer;
pub use types::Callbacks;
