//! The WireGuard implementation in Rust

#[macro_use]
extern crate tokio_core;
extern crate futures;

#[macro_use]
pub mod error;
pub mod device;
mod bindgen;

use device::Device;
use error::WgResult;

use std::io;
use std::net::SocketAddr;

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

    /// Things to send
    to_send: Option<(usize, SocketAddr)>,
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
            to_send: None,
        })
    }
}

impl Future for Wireguard {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        loop {
            // Check if a message needs to be processed
            if let Some((size, peer)) = self.to_send {
                // Write the message to the tunnel device
                let send_bytes = try_nb!(self.device.write(&self.buffer[..size]));

                // Set `to_send` to `None` if done
                self.to_send = None;
                println!("Wrote {}/{} bytes from {} to tunnel device",
                         send_bytes,
                         size,
                         peer);


                // Read from the tunnel device and write to the client
                // let read_bytes = try_nb!(self.device.read(&mut self.buffer));
                // try_nb!(self.server.send_to(&self.buffer[..read_bytes], &peer));
                // println!("Read {} bytes from tunnel device", read_bytes);
            }

            // Flush the device file descriptor
            try_nb!(self.device.flush());

            // If `to_send` is `None`, we can receive the next message from the client
            self.to_send = Some(try_nb!(self.server.recv_from(&mut self.buffer)));
        }
    }
}
