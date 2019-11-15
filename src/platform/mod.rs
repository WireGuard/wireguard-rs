mod endpoint;

pub mod bind;
pub mod tun;
pub mod uapi;

pub use endpoint::Endpoint;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(test)]
pub mod dummy;

#[cfg(target_os = "linux")]
pub use linux as plt;
