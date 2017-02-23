//! # WireGuard.rs
//! ## Fast, modern and secure VPN tunnel
//!
//! Target of this project is to have a user space Rust implementation of `WireGuard`.
#![deny(missing_docs)]

#[macro_use]
extern crate log;
extern crate libc;

#[macro_use]
mod error;
mod uapi;

pub use error::{WgResult, WgError};
use uapi::{WgDevice, WgIpMask, WgPeer};

use std::ffi::CString;
use std::fs::{create_dir, remove_file};
use std::mem::{size_of, size_of_val};
use std::ptr::null_mut;
use std::path::{Path, PathBuf};

use libc::{accept, bind, c_void, close, FIONREAD, free, ioctl, listen, malloc};
use libc::{read, socket, sockaddr, sockaddr_un, strncpy};
use libc::{poll, pollfd, POLLIN, POLLERR, POLLHUP, POLLNVAL};

/// The main `WireGuard` structure
pub struct WireGuard {
    /// The file descriptor of the socket
    fd: i32,
}

impl WireGuard {
    /// Creates a new `WireGuard` instance
    pub fn new(name: &str) -> WgResult<Self> {
        // Create the unix socket
        let fd = unsafe { socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            bail!("Could not create local socket.");
        }
        debug!("Created socket.");

        // Create the socket directory if not existing
        let mut socket_path = PathBuf::from("/var").join("run").join("wireguard");
        if !socket_path.exists() {
            create_dir(&socket_path)?;
            debug!("Created socket path: {}", socket_path.display());
        }
        Self::chmod(&socket_path, 0o700)?;

        // Finish the socket path
        socket_path.push(name);
        socket_path.set_extension("sock");
        if socket_path.exists() {
            remove_file(&socket_path)?;
            debug!("Removed existing socket: {}", socket_path.display());
        }

        // Create the `sockaddr_un` structure
        let mut sun_path = [0; 108];
        let src = CString::new(format!("{}", socket_path.display()))?;
        unsafe { strncpy(sun_path.as_mut_ptr(), src.as_ptr(), src.to_bytes().len()) };

        let sock_addr = sockaddr_un {
            sun_family: libc::AF_UNIX as u16,
            sun_path: sun_path,
        };

        // Bind the socket
        if unsafe {
            bind(fd,
                 &sock_addr as *const _ as *const sockaddr,
                 size_of_val(&sock_addr) as u32)
        } < 0 {
            bail!("Could not bind socket.");
        }
        debug!("Bound socket: {}", socket_path.display());

        // Listen on the socket
        if unsafe { listen(fd, 100) } < 0 {
            bail!("Could not listen on socket.");
        }
        debug!("Listening on socket.");

        // Return the `WireGuard` instance
        Ok(WireGuard { fd: fd })
    }

    /// Run the `WireGuard` instance
    pub fn run(&self) -> WgResult<()> {
        // A temporarily buffer to write in
        let mut buffer = null_mut::<c_void>();

        debug!("Waiting for connections.");

        loop {
            // Accept new connections
            let client = unsafe { accept(self.fd, null_mut(), null_mut()) };
            if client < 0 {
                Self::cleanup(buffer, client);
                error!("Can not 'accept' new connections.");
                break;
            }
            trace!("Accepted new connection.");

            // Poll for new events
            let pfd = pollfd {
                fd: client,
                events: POLLIN,
                revents: 0,
            };
            if unsafe { poll(&pfd as *const _ as *mut pollfd, 1, -1) < 0 } ||
               (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 || (pfd.revents & POLLIN) == 0 {
                Self::cleanup(buffer, client);
                bail!("Polling failed.");
            }
            trace!("Event polled.");

            // Get the size of the message
            let len = 0;
            let ret = unsafe { ioctl(client, FIONREAD, &len) };
            if ret < 0 || len == 0 {
                Self::cleanup(buffer, client);
                bail!("Call to 'ioctl' failed.");
            }
            trace!("Got message size.");

            // Allocate a buffer for the received data
            // TODO: memory leaks?
            buffer = unsafe { malloc(len) };
            if buffer.is_null() {
                Self::cleanup(buffer, client);
                bail!("Buffer memory allocation failed.");
            }
            trace!("Buffer memory allocated.");

            // Finally we receive the data
            let data_len = unsafe { read(client, buffer, len) };
            if data_len <= 0 {
                Self::cleanup(buffer, client);
                bail!("Could not receive data");
            }
            trace!("Received message.");

            // If `data_len` is 1 and it is a NULL byte, it's a "get" request, so we send our
            // device back.
            let device;
            if data_len == 1 && unsafe { buffer.offset(0) as u8 } == 0 {
                // TODO:
                // device = get_current_wireguard_device(&data_len);
                // unsafe { write(client, device, data_len as usize) };

            } else {
                let wgdev_size = size_of::<WgDevice>() as isize;
                let wgpeer_size = size_of::<WgPeer>() as isize;
                let wgipmask_size = size_of::<WgIpMask>() as isize;

                // Otherwise, we "set" the received wgdevice and send back the return status.
                // Check the message size
                if data_len < wgdev_size {
                    Self::cleanup(buffer, client);
                    bail!("Message size too small.")
                }

                device = buffer as *mut WgDevice;

                // Check that we're not out of bounds.
                unsafe {
                    let mut peer = device.offset(wgdev_size) as *mut WgPeer;
                    for _ in 0..*(*device).peers.num_peers.as_ref() {
                        // Calculate the current peer
                        let peer_offset = wgpeer_size + wgipmask_size * (*peer).num_ipmasks as isize;
                        peer = peer.offset(peer_offset);

                        if peer.offset(wgpeer_size) as *mut u8 > device.offset(data_len) as *mut u8 {
                            Self::cleanup(buffer, client);
                            bail!("Message out of bounds.");
                        }

                        if peer.offset(peer_offset) as *mut u8 > device.offset(data_len) as *mut u8 {
                            Self::cleanup(buffer, client);
                            bail!("Message out of bounds.");
                        }
                    }
                }

                // TODO:
                // let ret = set_current_wireguard_device(device);
                // unsafe { write(client, &ret, size_of_val(ret)) };
            }
        }

        Ok(())
    }

    /// Cleanup the buffer and client
    fn cleanup(buffer: *mut c_void, client: i32) {
        // Free the buffer
        if !buffer.is_null() {
            unsafe { free(buffer) };
        }

        // Close the client
        if client >= 0 {
            unsafe { close(client) };
        }
    }

    #[cfg(unix)]
    /// Sets the permissions to a given `Path`
    fn chmod(path: &Path, perms: u32) -> WgResult<()> {
        use std::os::unix::prelude::PermissionsExt;
        use std::fs::{set_permissions, Permissions};
        set_permissions(path, Permissions::from_mode(perms))?;
        Ok(())
    }

    #[cfg(windows)]
    /// Sets the permissions to a given `Path`
    fn chmod(_path: &Path, _perms: u32) -> WgResult<()> {
        Ok(())
    }
}
