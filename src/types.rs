use base64;
use std::fmt::{self, Display, Formatter};
use std::net::IpAddr;
use std::time::Duration;
use udp::Endpoint;

pub type PacketVec = Vec<u8>;

#[derive(Clone, Debug, Default)]
pub struct PeerInfo {
    pub pub_key: [u8; 32],
    pub psk: Option<[u8; 32]>,
    pub endpoint: Option<Endpoint>,
    pub allowed_ips: Vec<(IpAddr, u32)>,
    pub keepalive: Option<u16>,
}

impl PeerInfo {
    pub fn persistent_keepalive(&self) -> Option<Duration> {
        match self.keepalive {
            Some(keepalive) if keepalive > 0 => Some(Duration::from_secs(u64::from(keepalive))),
            _ => None
        }
    }
}

impl Display for PeerInfo {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let encoded = base64::encode(&self.pub_key);
        write!(f, "{}...{}", &encoded[..4], &encoded[encoded.len()-4..])
    }
}

#[derive(Clone, Debug, Default)]
pub struct InterfaceInfo {
    pub private_key: Option<[u8; 32]>,
    pub pub_key: Option<[u8; 32]>,
    pub listen_port: Option<u16>,
    pub fwmark: Option<u32>,
}
