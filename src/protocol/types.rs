// Copyright 2017 Sopium

// This file is part of WireGuard.rs.

// WireGuard.rs is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// WireGuard.rs is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with WireGuard.rs.  If not, see <https://www.gnu.org/licenses/>.

extern crate noise_protocol;
extern crate noise_sodiumoxide;
extern crate sodiumoxide;

use self::noise_protocol::DH;
use self::noise_sodiumoxide::X25519;
use self::sodiumoxide::randombytes::randombytes_into;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::time::SystemTime;

/// X25519 private key.
pub type X25519Key = <X25519 as DH>::Key;
/// X25519 pubkey key.
pub type X25519Pubkey = <X25519 as DH>::Pubkey;

/// Config info about a WireGuard peer.
#[derive(Clone)]
pub struct PeerInfo {
    /// Peer public key.
    pub peer_pubkey: X25519Pubkey,
    /// Peer endpoint.
    pub endpoint: Option<SocketAddr>,
    /// Allowed source IPs.
    pub allowed_ips: Vec<(IpAddr, u32)>,
    /// Persistent keep-alive interval.
    /// Valid values: 1 - 0xfffe.
    pub keep_alive_interval: Option<u16>,
}

/// Config info about a WireGuard interface.
pub struct WgInfo {
    /// Optional pre-shared key.
    pub psk: Option<[u8; 32]>,
    /// Self private key.
    pub key: X25519Key,
    /// Self public key.
    /// Should correspond to self private key.
    pub pubkey: X25519Pubkey,
}

/// State of WireGuard interface.
pub struct WgStateOut {
    /// Self public key.
    pub public_key: X25519Pubkey,
    /// Self private key.
    pub private_key: X25519Key,
    /// Pre-shared key.
    pub preshared_key: Option<[u8; 32]>,
    /// Peers.
    pub peers: Vec<PeerStateOut>,
}

/// State of a peer.
pub struct PeerStateOut {
    /// Public key.
    pub public_key: X25519Pubkey,
    /// Endpoint.
    pub endpoint: Option<SocketAddr>,
    /// Last handshake time.
    pub last_handshake_time: Option<SystemTime>,
    /// Received bytes.
    pub rx_bytes: u64,
    /// Sent bytes.
    pub tx_bytes: u64,
    /// Persistent keep-alive interval.
    pub persistent_keepalive_interval: Option<u16>,
    /// Allowed IP addresses.
    pub allowed_ips: Vec<(IpAddr, u32)>,
}

impl WgInfo {
    /// Create a new `WgInfo`.
    pub fn new(psk: Option<[u8; 32]>, key: X25519Key) -> Self {
        let pk = <X25519 as DH>::pubkey(&key);
        WgInfo {
            psk: psk,
            key: key,
            pubkey: pk,
        }
    }
}

/// Sender index or receiver index.
///
/// WireGuard treats an index as a `u32` in little endian.
/// Why not just treat it as a 4-byte array?
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Id(pub [u8; 4]);

impl Id {
    /// Generate a new random ID.
    pub fn gen() -> Id {
        let mut id = [0u8; 4];
        randombytes_into(&mut id);
        Id(id)
    }

    /// Create Id from a slice.
    ///
    /// # Panics
    ///
    /// Slice must be 4 bytes long.
    pub fn from_slice(id: &[u8]) -> Id {
        let mut ret = Id([0u8; 4]);
        ret.0.copy_from_slice(id);
        ret
    }

    /// As slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Id {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}
