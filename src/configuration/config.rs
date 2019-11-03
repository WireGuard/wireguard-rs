use spin::Mutex;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::SystemTime;
use x25519_dalek::{PublicKey, StaticSecret};

use super::*;
use bind::Owner;

/// The goal of the configuration interface is, among others,
/// to hide the IO implementations (over which the WG device is generic),
/// from the configuration and UAPI code.

/// Describes a snapshot of the state of a peer
pub struct PeerState {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake_time_sec: u64,
    pub last_handshake_time_nsec: u64,
    pub public_key: PublicKey,
    pub allowed_ips: Vec<(IpAddr, u32)>,
}

pub struct WireguardConfig<T: tun::Tun, B: bind::Platform> {
    wireguard: Wireguard<T, B>,
    network: Mutex<Option<B::Owner>>,
}

impl<T: tun::Tun, B: bind::Platform> WireguardConfig<T, B> {
    fn new(wg: Wireguard<T, B>) -> WireguardConfig<T, B> {
        WireguardConfig {
            wireguard: wg,
            network: Mutex::new(None),
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

    fn set_listen_port(&self, port: Option<u16>) -> Option<ConfigError>;

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
    fn remove_peer(&self, peer: &PublicKey);

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
    fn add_peer(&self, peer: &PublicKey) -> bool;

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
    fn set_preshared_key(&self, peer: &PublicKey, psk: Option<[u8; 32]>) -> Option<ConfigError>;

    /// Update the endpoint of the
    ///
    /// # Arguments
    ///
    /// - `peer': The public key of the peer
    /// - `psk`
    fn set_endpoint(&self, peer: &PublicKey, addr: SocketAddr) -> Option<ConfigError>;

    /// Update the endpoint of the
    ///
    /// # Arguments
    ///
    /// - `peer': The public key of the peer
    /// - `psk`
    fn set_persistent_keepalive_interval(
        &self,
        peer: &PublicKey,
        interval: usize,
    ) -> Option<ConfigError>;

    /// Remove all allowed IPs from the peer
    ///
    /// # Arguments
    ///
    /// - `peer': The public key of the peer
    ///
    /// # Returns
    ///
    /// An error if no such peer exists
    fn replace_allowed_ips(&self, peer: &PublicKey) -> Option<ConfigError>;

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
    fn add_allowed_ip(&self, peer: &PublicKey, ip: IpAddr, masklen: u32) -> Option<ConfigError>;

    /// Returns the state of all peers
    ///
    /// # Returns
    ///
    /// A list of structures describing the state of each peer
    fn get_peers(&self) -> Vec<PeerState>;
}

impl<T: tun::Tun, B: bind::Platform> Configuration for WireguardConfig<T, B> {
    fn set_private_key(&self, sk: Option<StaticSecret>) {
        self.wireguard.set_key(sk)
    }

    fn get_private_key(&self) -> Option<StaticSecret> {
        self.wireguard.get_sk()
    }

    fn get_protocol_version(&self) -> usize {
        1
    }

    fn set_listen_port(&self, port: Option<u16>) -> Option<ConfigError> {
        let mut bind = self.network.lock();

        // close the current listener
        *bind = None;

        // bind to new port
        if let Some(port) = port {
            // create new listener
            let (mut readers, writer, owner) = match B::bind(port) {
                Ok(r) => r,
                Err(_) => {
                    return Some(ConfigError::FailedToBind);
                }
            };

            // add readers/writer to wireguard
            self.wireguard.set_writer(writer);
            while let Some(reader) = readers.pop() {
                self.wireguard.add_reader(reader);
            }

            // create new UDP state
            *bind = Some(owner);
        }

        None
    }

    fn set_fwmark(&self, mark: Option<u32>) -> Option<ConfigError> {
        match self.network.lock().as_mut() {
            Some(bind) => {
                bind.set_fwmark(mark).unwrap(); // TODO: handle
                None
            }
            None => Some(ConfigError::NotListening),
        }
    }

    fn replace_peers(&self) {
        self.wireguard.clear_peers();
    }

    fn remove_peer(&self, peer: &PublicKey) {
        self.wireguard.remove_peer(peer);
    }

    fn add_peer(&self, peer: &PublicKey) -> bool {
        self.wireguard.add_peer(*peer);
        false
    }

    fn set_preshared_key(&self, peer: &PublicKey, psk: Option<[u8; 32]>) -> Option<ConfigError> {
        if self.wireguard.set_psk(*peer, psk) {
            None
        } else {
            Some(ConfigError::NoSuchPeer)
        }
    }

    fn set_endpoint(&self, peer: &PublicKey, addr: SocketAddr) -> Option<ConfigError> {
        match self.wireguard.lookup_peer(peer) {
            Some(peer) => {
                peer.router.set_endpoint(B::Endpoint::from_address(addr));
                None
            }
            None => Some(ConfigError::NoSuchPeer),
        }
    }

    fn set_persistent_keepalive_interval(
        &self,
        peer: &PublicKey,
        interval: usize,
    ) -> Option<ConfigError> {
        match self.wireguard.lookup_peer(peer) {
            Some(peer) => {
                peer.set_persistent_keepalive_interval(interval);
                None
            }
            None => Some(ConfigError::NoSuchPeer),
        }
    }

    fn replace_allowed_ips(&self, peer: &PublicKey) -> Option<ConfigError> {
        match self.wireguard.lookup_peer(peer) {
            Some(peer) => {
                peer.router.remove_allowed_ips();
                None
            }
            None => Some(ConfigError::NoSuchPeer),
        }
    }

    fn add_allowed_ip(&self, peer: &PublicKey, ip: IpAddr, masklen: u32) -> Option<ConfigError> {
        match self.wireguard.lookup_peer(peer) {
            Some(peer) => {
                peer.router.add_allowed_ip(ip, masklen);
                None
            }
            None => Some(ConfigError::NoSuchPeer),
        }
    }

    fn get_peers(&self) -> Vec<PeerState> {
        let peers = self.wireguard.list_peers();
        let mut state = Vec::with_capacity(peers.len());
        for p in peers {
            // convert the system time to (secs, nano) since epoch
            let last_handshake = (*p.walltime_last_handshake.lock())
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("There should be no earlier time");

            // extract state into PeerState
            state.push(PeerState {
                rx_bytes: p.rx_bytes.load(Ordering::Relaxed),
                tx_bytes: p.tx_bytes.load(Ordering::Relaxed),
                allowed_ips: p.router.list_allowed_ips(),
                last_handshake_time_nsec: last_handshake.subsec_nanos() as u64,
                last_handshake_time_sec: last_handshake.as_secs(),
                public_key: p.pk,
            })
        }
        state
    }
}
