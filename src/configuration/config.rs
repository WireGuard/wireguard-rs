use spin::Mutex;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};
use x25519_dalek::{PublicKey, StaticSecret};

use super::udp::Owner;
use super::*;

/// The goal of the configuration interface is, among others,
/// to hide the IO implementations (over which the WG device is generic),
/// from the configuration and UAPI code.
///
/// Furthermore it forms the simpler interface for embedding WireGuard in other applications,
/// and hides the complex types of the implementation from the host application.

/// Describes a snapshot of the state of a peer
pub struct PeerState {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake_time: Option<(u64, u64)>,
    pub public_key: PublicKey,
    pub allowed_ips: Vec<(IpAddr, u32)>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive_interval: u64,
    pub preshared_key: [u8; 32], // 0^32 is the "default value"
}

pub struct WireguardConfig<T: tun::Tun, B: udp::PlatformUDP> {
    wireguard: Wireguard<T, B>,
    fwmark: Mutex<Option<u32>>,
    network: Mutex<Option<B::Owner>>,
}

impl<T: tun::Tun, B: udp::PlatformUDP> WireguardConfig<T, B> {
    pub fn new(wg: Wireguard<T, B>) -> WireguardConfig<T, B> {
        WireguardConfig {
            wireguard: wg,
            fwmark: Mutex::new(None),
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

    fn set_listen_port(&self, port: Option<u16>) -> Result<(), ConfigError>;

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
    fn set_fwmark(&self, mark: Option<u32>) -> Result<(), ConfigError>;

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
    fn set_preshared_key(&self, peer: &PublicKey, psk: [u8; 32]);

    /// Update the endpoint of the
    ///
    /// # Arguments
    ///
    /// - `peer': The public key of the peer
    /// - `psk`
    fn set_endpoint(&self, peer: &PublicKey, addr: SocketAddr);

    /// Update the endpoint of the
    ///
    /// # Arguments
    ///
    /// - `peer': The public key of the peer
    /// - `psk`
    fn set_persistent_keepalive_interval(&self, peer: &PublicKey, secs: u64);

    /// Remove all allowed IPs from the peer
    ///
    /// # Arguments
    ///
    /// - `peer': The public key of the peer
    ///
    /// # Returns
    ///
    /// An error if no such peer exists
    fn replace_allowed_ips(&self, peer: &PublicKey);

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
    fn add_allowed_ip(&self, peer: &PublicKey, ip: IpAddr, masklen: u32);

    fn get_listen_port(&self) -> Option<u16>;

    /// Returns the state of all peers
    ///
    /// # Returns
    ///
    /// A list of structures describing the state of each peer
    fn get_peers(&self) -> Vec<PeerState>;

    fn get_fwmark(&self) -> Option<u32>;
}

impl<T: tun::Tun, B: udp::PlatformUDP> Configuration for WireguardConfig<T, B> {
    fn get_fwmark(&self) -> Option<u32> {
        self.network
            .lock()
            .as_ref()
            .and_then(|bind| bind.get_fwmark())
    }

    fn set_private_key(&self, sk: Option<StaticSecret>) {
        self.wireguard.set_key(sk)
    }

    fn get_private_key(&self) -> Option<StaticSecret> {
        self.wireguard.get_sk()
    }

    fn get_protocol_version(&self) -> usize {
        1
    }

    fn get_listen_port(&self) -> Option<u16> {
        let bind = self.network.lock();
        log::trace!("Config, Get listen port, bound: {}", bind.is_some());
        bind.as_ref().map(|bind| bind.get_port())
    }

    fn set_listen_port(&self, port: Option<u16>) -> Result<(), ConfigError> {
        log::trace!("Config, Set listen port: {:?}", port);

        let mut bind = self.network.lock();

        // close the current listener
        *bind = None;

        // bind to new port
        if let Some(port) = port {
            // create new listener
            let (mut readers, writer, mut owner) = match B::bind(port) {
                Ok(r) => r,
                Err(_) => {
                    return Err(ConfigError::FailedToBind);
                }
            };

            // set fwmark
            let _ = owner.set_fwmark(*self.fwmark.lock()); // TODO: handle

            // add readers/writer to wireguard
            self.wireguard.set_writer(writer);
            while let Some(reader) = readers.pop() {
                self.wireguard.add_reader(reader);
            }

            // create new UDP state
            *bind = Some(owner);
        }

        Ok(())
    }

    fn set_fwmark(&self, mark: Option<u32>) -> Result<(), ConfigError> {
        log::trace!("Config, Set fwmark: {:?}", mark);

        match self.network.lock().as_mut() {
            Some(bind) => {
                bind.set_fwmark(mark).unwrap(); // TODO: handle
                Ok(())
            }
            None => Err(ConfigError::NotListening),
        }
    }

    fn replace_peers(&self) {
        self.wireguard.clear_peers();
    }

    fn remove_peer(&self, peer: &PublicKey) {
        self.wireguard.remove_peer(peer);
    }

    fn add_peer(&self, peer: &PublicKey) -> bool {
        self.wireguard.add_peer(*peer)
    }

    fn set_preshared_key(&self, peer: &PublicKey, psk: [u8; 32]) {
        self.wireguard.set_psk(*peer, psk);
    }

    fn set_endpoint(&self, peer: &PublicKey, addr: SocketAddr) {
        if let Some(peer) = self.wireguard.lookup_peer(peer) {
            peer.router.set_endpoint(B::Endpoint::from_address(addr));
        }
    }

    fn set_persistent_keepalive_interval(&self, peer: &PublicKey, secs: u64) {
        if let Some(peer) = self.wireguard.lookup_peer(peer) {
            peer.set_persistent_keepalive_interval(secs);
        }
    }

    fn replace_allowed_ips(&self, peer: &PublicKey) {
        if let Some(peer) = self.wireguard.lookup_peer(peer) {
            peer.router.remove_allowed_ips();
        }
    }

    fn add_allowed_ip(&self, peer: &PublicKey, ip: IpAddr, masklen: u32) {
        if let Some(peer) = self.wireguard.lookup_peer(peer) {
            peer.router.add_allowed_ip(ip, masklen);
        }
    }

    fn get_peers(&self) -> Vec<PeerState> {
        let peers = self.wireguard.list_peers();
        let mut state = Vec::with_capacity(peers.len());

        for p in peers {
            // convert the system time to (secs, nano) since epoch
            let last_handshake_time = (*p.walltime_last_handshake.lock()).and_then(|t| {
                let duration = t
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0));
                Some((duration.as_secs(), duration.subsec_nanos() as u64))
            });

            if let Some(psk) = self.wireguard.get_psk(&p.pk) {
                // extract state into PeerState
                state.push(PeerState {
                    preshared_key: psk,
                    endpoint: p.router.get_endpoint(),
                    rx_bytes: p.rx_bytes.load(Ordering::Relaxed),
                    tx_bytes: p.tx_bytes.load(Ordering::Relaxed),
                    persistent_keepalive_interval: p.get_keepalive_interval(),
                    allowed_ips: p.router.list_allowed_ips(),
                    last_handshake_time,
                    public_key: p.pk,
                })
            }
        }
        state
    }
}
