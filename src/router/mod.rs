mod anti_replay;
mod constants;
mod device;
mod messages;
mod peer;
mod types;
mod workers;

#[cfg(test)]
mod tests;

use messages::TransportHeader;
use std::mem;

pub const SIZE_MESSAGE_PREFIX: usize = mem::size_of::<TransportHeader>();

pub use device::Device;
pub use peer::Peer;
