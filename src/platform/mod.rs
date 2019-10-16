use std::error::Error;

use super::wireguard::bind::Bind;
use super::wireguard::tun::Tun;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::PlatformTun;

pub trait UDPBind: Bind {
    type Closer;

    /// Bind to a new port, returning the reader/writer and
    /// an associated instance of the Closer type, which closes the UDP socket upon "drop".
    fn bind(port: u16) -> Result<(Self::Reader, Self::Writer, Self::Closer), Self::Error>;
}

pub trait TunBind: Tun {
    fn create(name: &str) -> Result<(Vec<Self::Reader>, Self::Writer, Self::MTU), Self::Error>;
}
