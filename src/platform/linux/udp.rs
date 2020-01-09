use super::super::udp::*;
use super::super::Endpoint;

use log;

use std::convert::TryInto;
use std::io;
use std::mem;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::RawFd;

pub struct EndpointV4 {
    dst: libc::sockaddr_in, // destination IP
    info: libc::in_pktinfo, // src & ifindex
}

pub struct EndpointV6 {
    dst: libc::sockaddr_in6, // destination IP
    info: libc::in6_pktinfo, // src & zone id
}

pub struct LinuxUDP();

pub struct LinuxOwner {
    port: u16,
    sock4: Option<RawFd>,
    sock6: Option<RawFd>,
}

pub enum LinuxUDPReader {
    V4(RawFd),
    V6(RawFd),
}

#[derive(Clone)]
pub struct LinuxUDPWriter {
    sock4: RawFd,
    sock6: RawFd,
}

pub enum LinuxEndpoint {
    V4(EndpointV4),
    V6(EndpointV6),
}

impl Endpoint for LinuxEndpoint {
    fn clear_src(&mut self) {
        match self {
            LinuxEndpoint::V4(EndpointV4 { ref mut info, .. }) => {
                info.ipi_ifindex = 0;
                info.ipi_spec_dst = libc::in_addr { s_addr: 0 };
            }
            LinuxEndpoint::V6(EndpointV6 { ref mut info, .. }) => {
                info.ipi6_addr = libc::in6_addr { s6_addr: [0; 16] };
                info.ipi6_ifindex = 0;
            }
        };
    }

    fn from_address(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => LinuxEndpoint::V4(EndpointV4 {
                dst: libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: addr.port(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from(*addr.ip()),
                    },
                    sin_zero: [0; 8],
                },
                info: libc::in_pktinfo {
                    ipi_ifindex: 0,                            // interface (0 is via routing table)
                    ipi_spec_dst: libc::in_addr { s_addr: 0 }, // src IP (dst of incoming packet)
                    ipi_addr: libc::in_addr {
                        // dst IP
                        s_addr: u32::from(*addr.ip()),
                    },
                },
            }),
            SocketAddr::V6(addr) => LinuxEndpoint::V6(EndpointV6 {
                dst: libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: addr.port(),
                    sin6_flowinfo: addr.flowinfo(),
                    sin6_addr: libc::in6_addr {
                        s6_addr: addr.ip().octets(),
                    },
                    sin6_scope_id: addr.scope_id(),
                },
                info: libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr { s6_addr: [0; 16] }, // src IP
                    ipi6_ifindex: 0,                                // zone id
                },
            }),
        }
    }

    fn into_address(&self) -> SocketAddr {
        match self {
            LinuxEndpoint::V4(EndpointV4 { ref dst, .. }) => {
                SocketAddr::V4(SocketAddrV4::new(
                    dst.sin_addr.s_addr.into(), // IPv4 addr
                    dst.sin_port,
                ))
            }
            LinuxEndpoint::V6(EndpointV6 { ref dst, .. }) => SocketAddr::V6(SocketAddrV6::new(
                u128::from_ne_bytes(dst.sin6_addr.s6_addr).into(), // IPv6 addr
                dst.sin6_port,
                dst.sin6_flowinfo,
                dst.sin6_scope_id,
            )),
        }
    }
}

impl LinuxUDPReader {
    fn read6(fd: RawFd, buf: &mut [u8]) -> Result<(usize, LinuxEndpoint), io::Error> {
        unimplemented!()
    }

    fn read4(fd: RawFd, buf: &mut [u8]) -> Result<(usize, LinuxEndpoint), io::Error> {
        unimplemented!()
    }
}

impl Reader<LinuxEndpoint> for LinuxUDPReader {
    type Error = io::Error;

    fn read(&self, buf: &mut [u8]) -> Result<(usize, LinuxEndpoint), Self::Error> {
        match self {
            Self::V4(fd) => Self::read4(*fd, buf),
            Self::V6(fd) => Self::read6(*fd, buf),
        }
    }
}

impl LinuxUDPWriter {
    fn write6(fd: RawFd, buf: &[u8], dst: &EndpointV6) -> Result<(), io::Error> {
        unimplemented!()
    }

    fn write4(fd: RawFd, buf: &[u8], dst: &EndpointV4) -> Result<(), io::Error> {
        unimplemented!()
    }
}

impl Writer<LinuxEndpoint> for LinuxUDPWriter {
    type Error = io::Error;

    fn write(&self, buf: &[u8], dst: &LinuxEndpoint) -> Result<(), Self::Error> {
        match dst {
            LinuxEndpoint::V4(ref end) => Self::write4(self.sock4, buf, end),
            LinuxEndpoint::V6(ref end) => Self::write6(self.sock6, buf, end),
        }
    }
}

impl Owner for LinuxOwner {
    type Error = io::Error;

    fn get_port(&self) -> u16 {
        self.port
    }

    fn set_fwmark(&mut self, value: Option<u32>) -> Result<(), Self::Error> {
        fn set_mark(fd: Option<RawFd>, value: u32) -> Result<(), io::Error> {
            if let Some(fd) = fd {
                let err = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_MARK,
                        mem::transmute(&value as *const u32),
                        mem::size_of_val(&value).try_into().unwrap(),
                    )
                };
                if err != 0 {
                    log::debug!("Failed to set fwmark: {}", err);
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "failed to set fwmark",
                    ));
                }
            }
            Ok(())
        }
        let value = value.unwrap_or(0);
        set_mark(self.sock6, value)?;
        set_mark(self.sock4, value)
    }
}

impl Drop for LinuxOwner {
    fn drop(&mut self) {
        self.sock4.map(|fd| unsafe { libc::close(fd) });
        self.sock6.map(|fd| unsafe { libc::close(fd) });
    }
}

impl UDP for LinuxUDP {
    type Error = io::Error;
    type Endpoint = LinuxEndpoint;
    type Reader = LinuxUDPReader;
    type Writer = LinuxUDPWriter;
}

impl LinuxUDP {
    /* Bind on all interfaces with IPv6.
     *
     * Arguments:
     *
     * - 'port', port to bind to (0 = any)
     *
     * Returns:
     *
     * Returns a tuple of the resulting port and socket.
     */
    fn bind6(port: u16) -> Result<(u16, RawFd), io::Error> {
        // create socket fd
        let fd: RawFd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to create socket",
            ));
        }

        // bind
        let mut sockaddr = libc::sockaddr_in6 {
            sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
            sin6_family: libc::AF_INET6.try_into().unwrap(),
            sin6_port: port.to_be(), // convert to network (big-endian) byteorder
            sin6_scope_id: 0,
            sin6_flowinfo: 0,
        };

        let err = unsafe {
            libc::bind(
                fd,
                mem::transmute(&sockaddr as *const libc::sockaddr_in6),
                mem::size_of_val(&sockaddr).try_into().unwrap(),
            )
        };

        if err != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to create socket",
            ));
        }

        // listen
        let err = unsafe { libc::listen(fd, 0) };
        if err != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to create socket",
            ));
        };

        // get the assigned port
        let mut socklen: libc::socklen_t = 0;
        let err = unsafe {
            libc::getsockname(
                fd,
                mem::transmute(&mut sockaddr as *mut libc::sockaddr_in6),
                &mut socklen as *mut libc::socklen_t,
            )
        };
        if err != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to create socket",
            ));
        }

        // basic sanity checks
        let new_port = u16::from_be(sockaddr.sin6_port);
        debug_assert_eq!(socklen, mem::size_of::<libc::sockaddr_in6>() as u32);
        debug_assert_eq!(sockaddr.sin6_family, libc::AF_INET6 as libc::sa_family_t);
        debug_assert_eq!(new_port, if port != 0 { port } else { new_port });
        return Ok((new_port, fd));
    }

    /* Bind on all interfaces with IPv4.
     *
     * Arguments:
     *
     * - 'port', port to bind to (0 = any)
     *
     * Returns:
     *
     * Returns a tuple of the resulting port and socket.
     */
    fn bind4(port: u16) -> Result<(u16, RawFd), io::Error> {
        // create socket fd
        let fd: RawFd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to create socket",
            ));
        }

        // bind
        let mut sockaddr = libc::sockaddr_in {
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(), // convert to network (big-endian) byteorder
            sin_zero: [0; 8],
        };

        let err = unsafe {
            libc::bind(
                fd,
                mem::transmute(&sockaddr as *const libc::sockaddr_in),
                mem::size_of_val(&sockaddr).try_into().unwrap(),
            )
        };

        if err != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to create socket",
            ));
        }

        // listen
        let err = unsafe { libc::listen(fd, 0) };
        if err != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to create socket",
            ));
        };

        // get the assigned port
        let mut socklen: libc::socklen_t = 0;
        let err = unsafe {
            libc::getsockname(
                fd,
                mem::transmute(&mut sockaddr as *mut libc::sockaddr_in),
                &mut socklen as *mut libc::socklen_t,
            )
        };
        if err != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to create socket",
            ));
        }

        // basic sanity checks
        let new_port = u16::from_be(sockaddr.sin_port);
        debug_assert_eq!(socklen, mem::size_of::<libc::sockaddr_in>() as u32);
        debug_assert_eq!(sockaddr.sin_family, libc::AF_INET as libc::sa_family_t);
        debug_assert_eq!(new_port, if port != 0 { port } else { new_port });
        return Ok((new_port, fd));
    }
}

impl PlatformUDP for LinuxUDP {
    type Owner = LinuxOwner;

    fn bind(mut port: u16) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error> {
        // attempt to bind on ipv6
        let bind6 = Self::bind6(port);
        if let Ok((new_port, _)) = bind6 {
            port = new_port;
        }

        // attempt to bind on ipv4 on the same port
        let bind4 = Self::bind4(port);
        if let Ok((new_port, _)) = bind4 {
            port = new_port;
        }

        // check if failed to bind on both
        if bind4.is_err() && bind6.is_err() {
            return Err(bind6.unwrap_err());
        }

        let sock6 = bind6.ok().map(|(_, fd)| fd);
        let sock4 = bind4.ok().map(|(_, fd)| fd);

        // create owner
        let owner = LinuxOwner {
            port,
            sock6: sock6,
            sock4: sock4,
        };

        // create readers
        let mut readers: Vec<Self::Reader> = Vec::with_capacity(2);
        sock6.map(|sock| readers.push(LinuxUDPReader::V6(sock)));
        sock4.map(|sock| readers.push(LinuxUDPReader::V4(sock)));
        debug_assert!(readers.len() > 0);

        // create writer
        let writer = LinuxUDPWriter {
            sock4: sock4.unwrap_or(-1),
            sock6: sock6.unwrap_or(-1),
        };

        Ok((readers, writer, owner))
    }
}
