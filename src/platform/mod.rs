mod endpoint;

pub mod bind;
pub mod tun;

pub use endpoint::Endpoint;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(test)]
pub mod dummy;

#[cfg(target_os = "linux")]
pub use linux::LinuxTun as TunInstance;
