use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::wireguard::Wireguard;
use crate::types::tun::Tun;
use crate::types::bind::Bind;

///
/// The goal of the configuration interface is, among others,
/// to hide the IO implementations (over which the WG device is generic),
/// from the configuration and UAPI code.

/// Describes a snapshot of the state of a peer
pub struct PeerState {
    rx_bytes: u64,
    tx_bytes: u64,
    last_handshake_time_sec: u64,
    last_handshake_time_nsec: u64,
    public_key: PublicKey,
    allowed_ips: Vec<(IpAddr, u32)>,
}

pub enum ConfigError {
    NoSuchPeer
}

impl ConfigError {

    fn errno(&self) -> i32 {
        match self {
            NoSuchPeer => 1,
        }
    }
}

/// Exposed configuration interface
pub trait Configuration {
    /// Updates the private key of the device
    ///
    /// # Arguments
    ///
    /// - `sk`: The new private key (or None, if the private key should be cleared)
    fn set_private_key(&self, sk: Option<StaticSecret>);

    /// Returns the private key of the device
    ///
    /// # Returns
    ///
    /// The private if set, otherwise None.
    fn get_private_key(&self) -> Option<StaticSecret>;

    /// Returns the protocol version of the device
    ///
    /// # Returns
    ///
    /// An integer indicating the protocol version
    fn get_protocol_version(&self) -> usize;

    fn set_listen_port(&self, port: u16) -> Option<ConfigError>;

    /// Set the firewall mark (or similar, depending on platform)
    ///
    /// # Arguments
    ///
    /// - `mark`: The fwmark value
    ///
    /// # Returns
    ///
    /// An error if this operation is not supported by the underlying
    /// "bind" implementation.
    fn set_fwmark(&self, mark: Option<u32>) -> Option<ConfigError>;

    /// Removes all peers from the device
    fn replace_peers(&self);

    /// Remove the peer from the
    ///
    /// # Arguments
    ///
    /// - `peer`: The public key of the peer to remove
    ///
    /// # Returns
    ///
    /// If the peer does not exists this operation is a noop
    fn remove_peer(&self, peer: PublicKey);

    /// Adds a new peer to the device
    ///
    /// # Arguments
    ///
    /// - `peer`: The public key of the peer to add
    ///
    /// # Returns
    ///
    /// A bool indicating if the peer was added.
    ///
    /// If the peer already exists this operation is a noop
    fn add_peer(&self, peer: PublicKey) -> bool;

    /// Update the psk of a peer
    ///
    /// # Arguments
    ///
    /// - `peer`: The public key of the peer
    /// - `psk`: The new psk or None if the psk should be unset
    ///
    /// # Returns
    ///
    /// An error if no such peer exists
    fn set_preshared_key(&self, peer: PublicKey, psk: Option<[u8; 32]>) -> Option<ConfigError>;

    /// Update the endpoint of the
    ///
    /// # Arguments
    ///
    /// - `peer': The public key of the peer
    /// - `psk`
    fn set_endpoint(&self, peer: PublicKey, addr: SocketAddr) -> Option<ConfigError>;

    /// Update the endpoint of the
    ///
    /// # Arguments
    ///
    /// - `peer': The public key of the peer
    /// - `psk`
    fn set_persistent_keepalive_interval(&self, peer: PublicKey) -> Option<ConfigError>;

    /// Remove all allowed IPs from the peer
    ///
    /// # Arguments
    ///
    /// - `peer': The public key of the peer
    ///
    /// # Returns
    ///
    /// An error if no such peer exists
    fn replace_allowed_ips(&self, peer: PublicKey) -> Option<ConfigError>;

    /// Add a new allowed subnet to the peer
    ///
    /// # Arguments
    ///
    /// - `peer`: The public key of the peer
    /// - `ip`: Subnet mask
    /// - `masklen`:
    ///
    /// # Returns
    ///
    /// An error if the peer does not exist
    ///
    /// # Note:
    ///
    /// The API must itself sanitize the (ip, masklen) set:
    /// The ip should be masked to remove any set bits right of the first "masklen" bits.
    fn add_allowed_ip(&self, peer: PublicKey, ip: IpAddr, masklen: u32) -> Option<ConfigError>;

    /// Returns the state of all peers
    ///
    /// # Returns
    ///
    /// A list of structures describing the state of each peer
    fn get_peers(&self) -> Vec<PeerState>;
}

impl <T : Tun, B : Bind>Configuration for Wireguard<T, B> {

    fn set_private_key(&self, sk : Option<StaticSecret>) {
        self.set_key(sk)
    }

    fn get_private_key(&self) -> Option<StaticSecret> {
        self.get_sk()
    }

    fn get_protocol_version(&self) -> usize {
        1
    }

    fn set_listen_port(&self, port : u16) -> Option<ConfigError> {
        None
    }

}