mod wireguard;
// mod config;
mod constants;
mod timers;

mod handshake;
mod router;
mod types;

#[cfg(test)]
mod tests;

/// The WireGuard sub-module contains a pure, configurable implementation of WireGuard.
/// The implementation is generic over:
/// 
/// - TUN type, specifying how packets are received on the interface side: a reader/writer and MTU reporting interface.
/// - Bind type, specifying how WireGuard messages are sent/received from the internet and what constitutes an "endpoint"

pub use wireguard::{Wireguard, Peer};

pub use types::bind;
pub use types::tun;
pub use types::Endpoint;