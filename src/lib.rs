//! The WireGuard implementation in Rust

#[macro_use]
extern crate log;

#[macro_use]
extern crate tokio_core;
extern crate futures;
extern crate mowl;

#[macro_use]
pub mod error;
pub mod device;
mod bindgen;

use device::Device;
use error::WgResult;

use std::io;
use std::net::SocketAddr;

use log::LogLevel;
use futures::{Future, Poll};
use tokio_core::net::UdpSocket;
use tokio_core::reactor::Handle;

/// The main tunnel structure
pub struct Wireguard {
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

impl Wireguard {
    /// Creates a new `Wireguard` instance
    pub fn new(handle: &Handle) -> WgResult<Self> {
        // Create a tunneling device
        let device = Device::dummy("wg")?;

        // Create a server for the tunnel
        let addr = "127.0.0.1:8080".to_owned().parse()?;
        let server = UdpSocket::bind(&addr, handle)?;

        Ok(Wireguard {
            device: device,
            server: server,
            buffer: vec![0; 1500],
            send_to_device: None,
            send_to_client: None,
        })
    }

    /// Initializes global logging
    pub fn init_logging(self, level: LogLevel) -> WgResult<Self> {
        mowl::init_with_level(level)?;
        Ok(self)
    }
}

impl Future for Wireguard {
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

                debug!("Wrote {}/{} bytes from {} to tunnel device",
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

                debug!("Wrote {}/{} bytes from the server to {}",
                       bytes_written,
                       length,
                       peer);
            }


            // If `send_to_device` is `None` we can receive the next message from the client
            self.send_to_device = Some(try_nb!(self.server.recv_from(&mut self.buffer)));

            // If `send_to_client` is `None` we can receive the next message from the tunnel device
            // self.send_to_client = Some(try_nb!(self.device.read(&mut self.buffer)));
            // debug!("Read {} bytes from tunnel device", self.send_to_client.0);
        }
    }
}
