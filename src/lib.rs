// Copyright 2017 Sascha Grunert, Guanhao Yin <sopium@mysterious.site>

// This file is part of WireGuard.rs.

// WireGuard.rs is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// WireGuard.rs is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with WireGuard.rs.  If not, see <https://www.gnu.org/licenses/>.

//! # WireGuard.rs
//! ## Fast, modern and secure VPN tunnel
//!
//! Target of this project is to have a user space Rust implementation of `WireGuard`.
#![deny(missing_docs)]

#![feature(integer_atomics)]
#![feature(retain_hash_collection)]

extern crate daemonize;
#[macro_use]
extern crate log;
extern crate libc;
#[macro_use]
extern crate nix;
#[macro_use]
extern crate error_chain;

pub mod tun;
mod crypto;
pub mod protocol;

pub mod error;
mod uapi;

use error::*;
use uapi::{WgDevice, WgIpMask, WgPeer};

use std::fs::{create_dir, remove_file};
use std::mem::size_of;
use std::path::{Path, PathBuf};

use libc::{FIONREAD, ioctl};

use nix::poll::{EventFlags, poll, PollFd, POLLIN, POLLERR, POLLHUP, POLLNVAL};
use nix::sys::socket::{accept, AddressFamily, bind, listen, SockAddr, SockType, SockFlag, socket, UnixAddr};
use nix::unistd::{close, read};

/// The main `WireGuard` structure
pub struct WireGuard {
    /// The file descriptor of the socket
    fd: i32,
}

impl WireGuard {
    /// Creates a new `WireGuard` instance
    pub fn new(name: &str) -> Result<Self> {
        // Create the unix socket
        let fd = socket(AddressFamily::Unix, SockType::Stream, SockFlag::empty(), 0)?;
        if fd < 0 {
            bail!("Could not create local socket.");
        }
        debug!("Created local socket.");

        // Create the socket directory if not existing
        let mut socket_path = if Path::new("/run").exists() {
            PathBuf::from("/run")
        } else {
            PathBuf::from("/var").join("run")
        };
        socket_path = socket_path.join("wireguard");

        if !socket_path.exists() {
            debug!("Creating socket path: {}", socket_path.display());
            create_dir(&socket_path)?;
        }
        debug!("Setting chmod 0700 of socket path: {}",
               socket_path.display());
        Self::chmod(&socket_path, 0o700)?;

        // Finish the socket path
        socket_path.push(name);
        socket_path.set_extension("sock");
        if socket_path.exists() {
            debug!("Removing existing socket: {}", socket_path.display());
            remove_file(&socket_path)?;
        }

        // Create the `sockaddr_un`
        let unix_addr = UnixAddr::new(&socket_path)?;
        let addr = SockAddr::Unix(unix_addr);

        // Bind the socket
        debug!("Binding socket.");
        bind(fd, &addr)?;

        // Listen on the socket
        debug!("Listening on socket.");
        listen(fd, 100)?;

        // Return the `WireGuard` instance
        Ok(WireGuard { fd: fd })
    }

    /// Run the `WireGuard` instance
    pub fn run(&self) -> Result<()> {
        // A temporarily buffer to write in
        let mut buffer = vec![];
        debug!("Waiting for connections.");

        loop {
            // Accept new connections
            trace!("Accepting new connection.");
            let client = accept(self.fd)?;
            if client < 0 {
                error!("Can not 'accept' new connections.");
                break;
            }

            // Poll for new events
            trace!("Polling for events.");
            let mut pollfd = [PollFd::new(client, POLLIN, EventFlags::empty())];
            poll(&mut pollfd, -1)?;

            // Check for the correct revents
            if let Some(re) = pollfd[0].revents() {
                if re.contains(POLLERR) || re.contains(POLLHUP) || re.contains(POLLNVAL) || !re.contains(POLLIN) {
                    close(client)?;
                    bail!("Polling failed.");
                }
            }

            // Get the size of the message
            trace!("Getting message size.");
            let message_len = 0;
            let ret = unsafe { ioctl(client, FIONREAD, &message_len) };
            if ret < 0 || message_len == 0 {
                close(client)?;
                bail!("Call to 'ioctl' failed.");
            }

            // Resize the vector
            buffer.resize(message_len, 0);

            // Finally we receive the data
            trace!("Reading message.");
            let data_len = read(client, buffer.as_mut_slice())?;
            if data_len == 0 {
                close(client)?;
                bail!("Could not receive data");
            }
            trace!("Message size: {}", data_len);

            // If `data_len` is 1 and it is a NULL byte, it's a "get" request, so we send our
            // device back.
            let device;
            if data_len == 1 && buffer[0] == 0 {
                trace!("Got 'get' request, sending back to device");
                // TODO:
                // device = get_current_wireguard_device(&data_len);
                // write(client, device, data_len as usize)?;

            } else {
                let wgdev_size = size_of::<WgDevice>();
                let wgpeer_size = size_of::<WgPeer>();
                let wgipmask_size = size_of::<WgIpMask>();

                // Otherwise, we "set" the received wgdevice and send back the return status.
                // Check the message size
                if data_len < wgdev_size {
                    close(client)?;
                    bail!("Message size too small (< {})", wgdev_size)
                }

                // Get the `WireGuard` device
                device = buffer.as_mut_ptr() as *mut WgDevice;

                // Check that we're not out of bounds.
                unsafe {
                    let mut peer = device.offset(wgdev_size as isize) as *mut WgPeer;
                    let num_peers = *(*device).peers.num_peers.as_ref();
                    trace!("Number of peers: {}", num_peers);

                    for i in 0..num_peers {
                        trace!("Processing peer {}", i);

                        // Calculate the current peer
                        let cur_peer_offset = wgpeer_size + wgipmask_size * (*peer).num_ipmasks as usize;
                        peer = peer.offset(cur_peer_offset as isize);

                        if peer.offset(wgpeer_size as isize) as *mut u8 > device.offset(data_len as isize) as *mut u8 {
                            close(client)?;
                            bail!("Message out of bounds, device data offset lower than overall peer offset.");
                        }

                        if peer.offset(cur_peer_offset as isize) as *mut u8 >
                           device.offset(data_len as isize) as *mut u8 {
                            close(client)?;
                            bail!("Message out of bounds, device data offset lower than current peer offset");
                        }
                    }
                }

                // TODO:
                // let ret = set_current_wireguard_device(device);
                // write(client, &ret, size_of_val(ret))?;
            }
        }

        Ok(())
    }

    #[cfg(unix)]
    /// Sets the permissions to a given `Path`
    fn chmod(path: &Path, perms: u32) -> Result<()> {
        use std::os::unix::prelude::PermissionsExt;
        use std::fs::{set_permissions, Permissions};
        set_permissions(path, Permissions::from_mode(perms))?;
        Ok(())
    }

    #[cfg(windows)]
    /// Sets the permissions to a given `Path`
    fn chmod(_path: &Path, _perms: u32) -> Result<()> {
        Ok(())
    }
}
