use std::error::Error;

use super::wireguard::bind::Bind;
use super::wireguard::tun::Tun;
use super::wireguard::Endpoint;

#[cfg(test)]
mod dummy;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::LinuxTun as TunInstance;

pub trait BindOwner: Send {
    type Error: Error;

    fn set_fwmark(&self, value: Option<u32>) -> Option<Self::Error>;
}

pub trait PlatformBind: Bind {
    type Owner: BindOwner;

    /// Bind to a new port, returning the reader/writer and
    /// an associated instance of the owner type, which closes the UDP socket upon "drop"
    /// and enables configuration of the fwmark value.
    fn bind(port: u16) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error>;
}

pub trait PlatformTun: Tun {
    fn create(name: &str) -> Result<(Vec<Self::Reader>, Self::Writer, Self::MTU), Self::Error>;
}
