//! Tunnel device handling
use std::env::temp_dir;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use bindgen;
use libc::ioctl;
use error::WgResult;

#[derive(Debug)]
/// A certain device
pub struct Device {
    /// The interface name
    name: String,

    /// The tunnel device file descriptor
    fd: File,

    /// The full path to the file
    path: PathBuf,

    /// Dummy indicator
    is_dummy: bool,

    /// A read/write counter
    rw_count: u64,
}

impl Device {
    /// Create a new tunneling `Device`
    pub fn new(name: &str) -> WgResult<Self> {
        // Get a file descriptor to the operating system
        let path = "/dev/net/tun";
        let fd = OpenOptions::new().read(true).write(true).open(path)?;

        // Get the default interface options
        let mut ifr = bindgen::ifreq::new();

        {
            // Set the interface name
            let ifr_name = unsafe { ifr.ifr_ifrn.ifrn_name.as_mut() };
            for (index, character) in name.as_bytes().iter().enumerate() {
                if index >= bindgen::IFNAMSIZ as usize - 1 {
                    bail!("Interface name too long.");
                }
                ifr_name[index] = *character as i8;
            }

            // Set the interface flags
            let ifr_flags = unsafe { ifr.ifr_ifru.ifru_flags.as_mut() };
            *ifr_flags = (bindgen::IFF_TUN | bindgen::IFF_NO_PI) as i16;
        }

        // Create the tunnel device
        if unsafe { ioctl(fd.as_raw_fd(), bindgen::TUNSETIFF, &ifr) < 0 } {
            bail!("Device creation failed.");
        }

        Ok(Device {
            name: name.to_owned(),
            fd: fd,
            path: PathBuf::from(path),
            is_dummy: false,
            rw_count: 0,
        })
    }

    /// Create a dummy device for testing
    pub fn dummy(name: &str) -> WgResult<Self> {
        // Place the dummy in the sytems default temp dir
        let path = temp_dir().join(name);

        // Create a file descriptor
        let fd = OpenOptions::new().create(true)
            .read(true)
            .write(true)
            .open(&path)?;
        Ok(Device {
            name: name.to_owned(),
            fd: fd,
            path: path,
            is_dummy: true,
            rw_count: 0,
        })
    }

    /// Reads a frame from the device, returns the number of bytes read
    pub fn read(&mut self, mut buffer: &mut [u8]) -> WgResult<usize> {
        // Increment the read/write count
        self.increment_rw_count();

        // Read from the file descriptor
        Ok(self.fd.read(&mut buffer)?)
    }

    /// Write a frame to the device
    pub fn write(&mut self, data: &[u8]) -> WgResult<usize> {
        // Increment the read/write count
        self.increment_rw_count();

        // Write the data
        let size = self.fd.write(data)?;

        // Flush the device file descriptor
        self.fd.flush()?;

        Ok(size)
    }

    /// Increment the read/write count
    fn increment_rw_count(&mut self) {
        self.rw_count = self.rw_count.saturating_add(1);
    }

    /// Flush the device
    pub fn flush(&mut self) -> WgResult<()> {
        Ok(self.fd.flush()?)
    }

    /// Returns `true` if the device is a dummy
    pub fn is_dummy(&self) -> bool {
        self.is_dummy
    }

    /// Returns the device name
    pub fn get_name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns the read/write counter of the device
    pub fn get_rw_count(&self) -> u64 {
        self.rw_count
    }

    /// Returns a reference to the internal file descriptor
    pub fn get_fd(&self) -> &File {
        &self.fd
    }

    /// Returns a reference to the path of the file
    pub fn get_path(&self) -> &Path {
        &self.path
    }
}
