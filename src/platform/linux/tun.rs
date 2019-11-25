use super::super::tun::*;

use libc::*;

use std::error::Error;
use std::fmt;
use std::os::raw::c_short;
use std::os::unix::io::RawFd;
use std::thread;
use std::time::Duration;

const IFNAMSIZ: usize = 16;
const TUNSETIFF: u64 = 0x4004_54ca;

const IFF_UP: i16 = 0x1;
const IFF_RUNNING: i16 = 0x40;

const IFF_TUN: c_short = 0x0001;
const IFF_NO_PI: c_short = 0x1000;

const CLONE_DEVICE_PATH: &'static [u8] = b"/dev/net/tun\0";

const TUN_MAGIC: u8 = b'T';
const TUN_SET_IFF: u8 = 202;

#[repr(C)]
struct Ifreq {
    name: [u8; libc::IFNAMSIZ],
    flags: c_short,
    _pad: [u8; 64],
}

pub struct LinuxTun {
    events: Vec<TunEvent>,
}

pub struct LinuxTunReader {
    fd: RawFd,
}

pub struct LinuxTunWriter {
    fd: RawFd,
}

/* Listens for netlink messages
 * announcing an MTU update for the interface
 */
#[derive(Clone)]
pub struct LinuxTunStatus {
    first: bool,
}

#[derive(Debug)]
pub enum LinuxTunError {
    InvalidTunDeviceName,
    FailedToOpenCloneDevice,
    SetIFFIoctlFailed,
    Closed, // TODO
}

impl fmt::Display for LinuxTunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinuxTunError::InvalidTunDeviceName => write!(f, "Invalid name (too long)"),
            LinuxTunError::FailedToOpenCloneDevice => {
                write!(f, "Failed to obtain fd for clone device")
            }
            LinuxTunError::SetIFFIoctlFailed => {
                write!(f, "set_iff ioctl failed (insufficient permissions?)")
            }
            LinuxTunError::Closed => write!(f, "The tunnel has been closed"),
        }
    }
}

impl Error for LinuxTunError {
    fn description(&self) -> &str {
        unimplemented!()
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        unimplemented!()
    }
}

impl Reader for LinuxTunReader {
    type Error = LinuxTunError;

    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Self::Error> {
        /*
        debug_assert!(
            offset < buf.len(),
            "There is no space for the body of the read"
        );
        */
        let n: isize =
            unsafe { read(self.fd, buf[offset..].as_mut_ptr() as _, buf.len() - offset) };
        if n < 0 {
            Err(LinuxTunError::Closed)
        } else {
            // conversion is safe
            Ok(n as usize)
        }
    }
}

impl Writer for LinuxTunWriter {
    type Error = LinuxTunError;

    fn write(&self, src: &[u8]) -> Result<(), Self::Error> {
        match unsafe { write(self.fd, src.as_ptr() as _, src.len() as _) } {
            -1 => Err(LinuxTunError::Closed),
            _ => Ok(()),
        }
    }
}

impl Status for LinuxTunStatus {
    type Error = LinuxTunError;

    fn event(&mut self) -> Result<TunEvent, Self::Error> {
        if self.first {
            self.first = false;
            return Ok(TunEvent::Up(1420));
        }

        loop {
            thread::sleep(Duration::from_secs(60 * 60));
        }
    }
}

impl Tun for LinuxTun {
    type Error = LinuxTunError;
    type Reader = LinuxTunReader;
    type Writer = LinuxTunWriter;
}

impl PlatformTun for LinuxTun {
    type Status = LinuxTunStatus;

    fn create(name: &str) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Status), Self::Error> {
        // construct request struct
        let mut req = Ifreq {
            name: [0u8; libc::IFNAMSIZ],
            flags: (libc::IFF_TUN | libc::IFF_NO_PI) as c_short,
            _pad: [0u8; 64],
        };

        // sanity check length of device name
        let bs = name.as_bytes();
        if bs.len() > libc::IFNAMSIZ - 1 {
            return Err(LinuxTunError::InvalidTunDeviceName);
        }
        req.name[..bs.len()].copy_from_slice(bs);

        // open clone device
        let fd: RawFd = match unsafe { open(CLONE_DEVICE_PATH.as_ptr() as _, O_RDWR) } {
            -1 => return Err(LinuxTunError::FailedToOpenCloneDevice),
            fd => fd,
        };
        assert!(fd >= 0);

        // create TUN device
        if unsafe { ioctl(fd, TUNSETIFF as _, &req) } < 0 {
            return Err(LinuxTunError::SetIFFIoctlFailed);
        }

        // create PlatformTunMTU instance
        Ok((
            vec![LinuxTunReader { fd }], // TODO: enable multi-queue for Linux
            LinuxTunWriter { fd },
            LinuxTunStatus { first: true },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn is_root() -> bool {
        match env::var("USER") {
            Ok(val) => val == "root",
            Err(_) => false,
        }
    }

    #[test]
    fn test_tun_create() {
        if !is_root() {
            return;
        }
        let (readers, writers, mtu) = LinuxTun::create("test").unwrap();
        // TODO: test (any good idea how?)
    }
}
