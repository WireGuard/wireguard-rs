//! # WireGuard.rs
//! ## Fast, modern and secure VPN tunnel
//!
//! Target of this project is to have a user space Rust implementation of `WireGuard`.
#![deny(missing_docs)]

#[macro_use]
extern crate log;

#[macro_use]
extern crate tokio_core;
extern crate futures;
extern crate mowl;

#[macro_use]
mod error;
mod device;
mod bindgen;

pub use device::Device;
pub use error::{WgResult, WgError};

use std::io;
use std::net::SocketAddr;
use std::str::FromStr;

use log::LogLevel;
use futures::{Async, Future, Poll};
use tokio_core::net::UdpSocket;
use tokio_core::reactor::{Core, Handle};

/// The main `WireGuard` structure
pub struct WireGuard {
    /// The tokio core which runs the server
    core: Core,

    /// The `WireGuard` future for tokio
    tunnel: WireGuardFuture,
}

impl WireGuard {
    /// Creates a new `WireGuard` instance
    pub fn new(addr: &str) -> WgResult<Self> {
        WireGuard::create(addr, false)
    }

    /// Create a new dummy `WireGuard` instance listening on "127.0.0.1:8080"
    pub fn dummy() -> WgResult<Self> {
        WireGuard::create("127.0.0.1:8080", true)
    }

    /// Internal `WireGuard` creation method
    fn create(addr: &str, dummy: bool) -> WgResult<Self> {
        // Create a new tokio core
        let core = Core::new()?;

        /// Create a tunnel instance
        let tunnel = WireGuardFuture::new(&core.handle(), addr, dummy)?;

        /// Return the `WireGuard` instance
        Ok(WireGuard {
            core: core,
            tunnel: tunnel,
        })
    }

    /// Run the server, consumes the `WireGuard` instance
    pub fn run(mut self) -> WgResult<()> {
        Ok(self.core.run(self.tunnel)?)
    }

    /// Initializes global logging
    pub fn init_logging(self, level: LogLevel) -> WgResult<Self> {
        mowl::init_with_level(level)?;
        Ok(self)
    }

    /// Returns the socket address of the server
    pub fn get_addr(&self) -> WgResult<SocketAddr> {
        Ok(self.tunnel.server.local_addr()?)
    }

    /// Returns a reference to the tunneling device
    pub fn get_device(&self) -> &Device {
        &self.tunnel.device
    }
}

#[derive(Debug)]
/// The main `WireGuard` future
pub struct WireGuardFuture {
    /// A tunneling device
    device: Device,

    /// The VPN server socket
    server: UdpSocket,

    /// An internal packet buffer
    buffer: Vec<u8>,

    /// Packets to send to the tunneling device
    send_to_device: Option<(usize, SocketAddr)>,

    /// Packets to send to the client
    send_to_client: Option<(usize, SocketAddr)>,
}

impl WireGuardFuture {
    /// Creates a new `WireGuardFuture`
    pub fn new(handle: &Handle, addr: &str, dummy: bool) -> WgResult<Self> {
        // Create a tunneling device
        let device = if dummy {
            Device::dummy()?
        } else {
            Device::new("wg")?
        };

        // Create a server for the tunnel
        let sock_addr = SocketAddr::from_str(addr)?;
        let server = UdpSocket::bind(&sock_addr, handle)?;

        /// Return the `WireGuardFuture` instance
        Ok(WireGuardFuture {
            device: device,
            server: server,
            buffer: vec![0; 1500],
            send_to_device: None,
            send_to_client: None,
        })
    }
}

impl Future for WireGuardFuture {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        loop {
            // Process message from the clients
            if let Some((length, peer)) = self.send_to_device {
                // Write the message to the tunnel device
                let bytes_written = try_nb!(self.device.write(&self.buffer[..length]));

                // Set to `None` if transmission is done
                self.send_to_device = None;

                info!("Wrote {}/{} bytes from {} to tunnel device",
                      bytes_written,
                      length,
                      peer);
            }

            // Process message from the tunneling device
            if let Some((length, peer)) = self.send_to_client {
                // Read from the tunnel device and write to the client
                let bytes_written = try_nb!(self.server.send_to(&self.buffer[..length], &peer));

                // Set to `None` if transmission is done
                self.send_to_client = None;

                info!("Wrote {}/{} bytes from the server to {}",
                      bytes_written,
                      length,
                      peer);
            }


            // If `send_to_device` is `None` we can receive the next message from the client
            self.send_to_device = Some(try_nb!(self.server.recv_from(&mut self.buffer)));

            // If `send_to_client` is `None` we can receive the next message from the tunnel device
            // self.send_to_client = Some(try_nb!(self.device.read(&mut self.buffer)));
            // info!("Read {} bytes from tunnel device", self.send_to_client.0);

            // Stop the future when running in test mode
            if self.device.is_dummy() && self.device.get_rw_count() > 2 {
                return Ok(Async::Ready(()));
            }
        }
    }
}
