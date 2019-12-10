mod constants;
mod timers;
mod wireguard;

mod endpoint;
mod handshake;
mod peer;
mod queue;
mod router;
mod types;

#[cfg(test)]
mod tests;

pub use peer::Peer;
pub use wireguard::Wireguard;

#[cfg(test)]
pub use types::dummy_keypair;

#[cfg(test)]
use super::platform::dummy;

use super::platform::{tun, udp, Endpoint};
use peer::PeerInner;
use types::KeyPair;
