use super::super::tun::*;

use libc;

use std::error::Error;
use std::fmt;
use std::mem;
use std::os::raw::c_short;
use std::os::unix::io::RawFd;

const TUNSETIFF: u64 = 0x4004_54ca;
const CLONE_DEVICE_PATH: &'static [u8] = b"/dev/net/tun\0";

#[repr(C)]
struct Ifreq {
    name: [u8; libc::IFNAMSIZ],
    flags: c_short,
    _pad: [u8; 64],
}

// man 7 rtnetlink
// Layout from: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/rtnetlink.h#L516
#[repr(C)]
struct IfInfomsg {
    ifi_family: libc::c_uchar,
    __ifi_pad: libc::c_uchar,
    ifi_type: libc::c_ushort,
    ifi_index: libc::c_int,
    ifi_flags: libc::c_uint,
    ifi_change: libc::c_uint,
}

pub struct LinuxTun {}

pub struct LinuxTunReader {
    fd: RawFd,
}

pub struct LinuxTunWriter {
    fd: RawFd,
}

pub struct LinuxTunStatus {
    events: Vec<TunEvent>,
    index: i32,
    name: [u8; libc::IFNAMSIZ],
    fd: RawFd,
}

#[derive(Debug)]
pub enum LinuxTunError {
    InvalidTunDeviceName,
    FailedToOpenCloneDevice,
    SetIFFIoctlFailed,
    GetMTUIoctlFailed,
    NetlinkFailure,
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
            LinuxTunError::GetMTUIoctlFailed => write!(f, "ifmtu ioctl failed"),
            LinuxTunError::NetlinkFailure => write!(f, "Netlink listener error"),
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
            unsafe { libc::read(self.fd, buf[offset..].as_mut_ptr() as _, buf.len() - offset) };
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
        match unsafe { libc::write(self.fd, src.as_ptr() as _, src.len() as _) } {
            -1 => Err(LinuxTunError::Closed),
            _ => Ok(()),
        }
    }
}

fn get_ifindex(name: &[u8; libc::IFNAMSIZ]) -> i32 {
    debug_assert_eq!(
        name[libc::IFNAMSIZ - 1],
        0,
        "name buffer not null-terminated"
    );

    let name = *name;
    let idx = unsafe {
        let ptr: *const libc::c_char = mem::transmute(&name);
        libc::if_nametoindex(ptr)
    };
    idx as i32
}

fn get_mtu(name: &[u8; libc::IFNAMSIZ]) -> Result<usize, LinuxTunError> {
    #[repr(C)]
    struct arg {
        name: [u8; libc::IFNAMSIZ],
        mtu: u32,
    }

    debug_assert_eq!(
        name[libc::IFNAMSIZ - 1],
        0,
        "name buffer not null-terminated"
    );

    // create socket
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(LinuxTunError::GetMTUIoctlFailed);
    }

    // do SIOCGIFMTU ioctl
    let buf = arg {
        name: *name,
        mtu: 0,
    };
    let err = unsafe {
        let ptr: &libc::c_void = mem::transmute(&buf);
        libc::ioctl(fd, libc::SIOCGIFMTU, ptr)
    };

    // close socket
    unsafe { libc::close(fd) };

    // handle error from ioctl
    if err != 0 {
        return Err(LinuxTunError::GetMTUIoctlFailed);
    }

    // upcast to usize
    Ok(buf.mtu as usize)
}

impl Status for LinuxTunStatus {
    type Error = LinuxTunError;

    fn event(&mut self) -> Result<TunEvent, Self::Error> {
        const DONE: u16 = libc::NLMSG_DONE as u16;
        const ERROR: u16 = libc::NLMSG_ERROR as u16;
        const INFO_SIZE: usize = mem::size_of::<IfInfomsg>();
        const HDR_SIZE: usize = mem::size_of::<libc::nlmsghdr>();

        let mut buf = [0u8; 1 << 12];
        log::debug!("netlink, fetch event (fd = {})", self.fd);
        loop {
            // attempt to return a buffered event
            if let Some(event) = self.events.pop() {
                return Ok(event);
            }

            // read message
            let size: libc::ssize_t =
                unsafe { libc::recv(self.fd, mem::transmute(&mut buf), buf.len(), 0) };
            if size < 0 {
                break Err(LinuxTunError::NetlinkFailure);
            }

            // cut buffer to size
            let size: usize = size as usize;
            let mut remain = &buf[..size];
            log::debug!("netlink, recieved message ({} bytes)", size);

            // handle messages
            while remain.len() >= HDR_SIZE {
                // extract the header
                assert!(remain.len() > HDR_SIZE);
                let hdr: libc::nlmsghdr = unsafe {
                    let mut hdr = [0u8; HDR_SIZE];
                    hdr.copy_from_slice(&remain[..HDR_SIZE]);
                    mem::transmute(hdr)
                };

                // upcast length
                let body: &[u8] = &remain[HDR_SIZE..];
                let msg_len: usize = hdr.nlmsg_len as usize;
                assert!(msg_len <= remain.len(), "malformed netlink message");

                // handle message body
                match hdr.nlmsg_type {
                    DONE => break,
                    ERROR => break,
                    libc::RTM_NEWLINK => {
                        // extract info struct
                        if body.len() < INFO_SIZE {
                            return Err(LinuxTunError::NetlinkFailure);
                        }
                        let info: IfInfomsg = unsafe {
                            let mut info = [0u8; INFO_SIZE];
                            info.copy_from_slice(&body[..INFO_SIZE]);
                            mem::transmute(info)
                        };

                        // trace log
                        log::trace!(
                            "netlink, IfInfomsg{{ family = {}, type = {}, index = {}, flags = {}, change = {}}}",
                            info.ifi_family,
                            info.ifi_type,
                            info.ifi_index,
                            info.ifi_flags,
                            info.ifi_change,
                        );
                        debug_assert_eq!(info.__ifi_pad, 0);

                        if info.ifi_index == self.index {
                            // handle up / down
                            if info.ifi_flags & (libc::IFF_UP as u32) != 0 {
                                let mtu = get_mtu(&self.name)?;
                                log::trace!("netlink, up event, mtu = {}", mtu);
                                self.events.push(TunEvent::Up(mtu));
                            } else {
                                log::trace!("netlink, down event");
                                self.events.push(TunEvent::Down);
                            }
                        }
                    }
                    _ => (),
                };

                // go to next message
                remain = &remain[msg_len..];
            }
        }
    }
}

impl LinuxTunStatus {
    const RTNLGRP_LINK: libc::c_uint = 1;
    const RTNLGRP_IPV4_IFADDR: libc::c_uint = 5;
    const RTNLGRP_IPV6_IFADDR: libc::c_uint = 9;

    fn new(name: [u8; libc::IFNAMSIZ]) -> Result<LinuxTunStatus, LinuxTunError> {
        // create netlink socket
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
        if fd < 0 {
            return Err(LinuxTunError::Closed);
        }

        // prepare address (specify groups)
        let groups = (1 << (Self::RTNLGRP_LINK - 1))
            | (1 << (Self::RTNLGRP_IPV4_IFADDR - 1))
            | (1 << (Self::RTNLGRP_IPV6_IFADDR - 1));

        let mut sockaddr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        sockaddr.nl_family = libc::AF_NETLINK as u16;
        sockaddr.nl_groups = groups;
        sockaddr.nl_pid = 0;

        // attempt to bind
        let res = unsafe {
            libc::bind(
                fd,
                mem::transmute(&mut sockaddr),
                mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };

        if res != 0 {
            Err(LinuxTunError::Closed)
        } else {
            Ok(LinuxTunStatus {
                events: vec![
                    #[cfg(feature = "start_up")]
                    TunEvent::Up(1500),
                ],
                index: get_ifindex(&name),
                fd,
                name,
            })
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
        let fd: RawFd = match unsafe { libc::open(CLONE_DEVICE_PATH.as_ptr() as _, libc::O_RDWR) } {
            -1 => return Err(LinuxTunError::FailedToOpenCloneDevice),
            fd => fd,
        };
        assert!(fd >= 0);

        // create TUN device
        if unsafe { libc::ioctl(fd, TUNSETIFF as _, &req) } < 0 {
            return Err(LinuxTunError::SetIFFIoctlFailed);
        }

        // create PlatformTunMTU instance
        Ok((
            vec![LinuxTunReader { fd }], // TODO: use multi-queue for Linux
            LinuxTunWriter { fd },
            LinuxTunStatus::new(req.name)?,
        ))
    }
}
