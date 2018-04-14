#![allow(unused)]

use std::{fmt, io, mem};
use std::net::{self, SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, RawFd};

use futures::{Async, Future, Poll};
use libc;
use mio;
use nix::{self, errno::Errno};
use nix::sys::{uio::IoVec, socket::{CmsgSpace, ControlMessage, UnknownCmsg, MsgFlags, SockAddr, recvmsg}};
use socket2::{Socket, Domain, Type, Protocol};

use tokio_core::reactor::{Handle, PollEvented};

/// An I/O object representing a UDP socket.
pub struct UdpSocket {
    io4: PollEvented<mio::net::UdpSocket>,
    io6: PollEvented<mio::net::UdpSocket>,
    handle: Handle,
}

/// IPV6_RECVPKTINFO is missing from the libc crate. Value taken from https://git.io/vxNel.
pub const IPV6_RECVPKTINFO : i32 = 61;
pub const IP_PKTINFO       : i32 = 26;

#[repr(C)]
struct in6_pktinfo {
    ipi6_addr    : libc::in6_addr,
    ipi6_ifindex : libc::c_uint
}

#[repr(C)]
struct in_pktinfo {
    ipi_ifindex  : libc::c_uint,
    ipi_spec_dst : libc::in_addr,
    ipi_addr     : libc::in_addr,
}

mod frame;
pub use self::frame::{UdpChannel, UdpFramed, VecUdpCodec, PeerServerMessage};

impl UdpSocket {
    pub fn bind(port: u16, handle: Handle) -> io::Result<UdpSocket> {
        let socket4 = Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp()))?;
        let socket6 = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp()))?;

        let on: libc::c_int = 1;
        unsafe {
            let ret = libc::setsockopt(socket4.as_raw_fd(),
                                       libc::IPPROTO_IP,
                                       IP_PKTINFO,
                                       &on as *const _ as *const libc::c_void,
                                       mem::size_of_val(&on) as libc::socklen_t);
            if ret != 0 {
                let err: Result<(), _> = Err(io::Error::last_os_error());
                err.expect("setsockopt failed");
            }
            debug!("set IP_PKTINFO");
        }

        unsafe {
            let ret = libc::setsockopt(socket6.as_raw_fd(),
                                       libc::IPPROTO_IPV6,
                                       IPV6_RECVPKTINFO,
                                       &on as *const _ as *const libc::c_void,
                                       mem::size_of_val(&on) as libc::socklen_t);
            if ret != 0 {
                let err: Result<(), _> = Err(io::Error::last_os_error());
                err.expect("setsockopt failed");
            }

            debug!("set IPV6_PKTINFO");
        }

        socket4.set_nonblocking(true)?;
        socket4.set_reuse_address(true)?;

        socket6.set_only_v6(true)?;
        socket6.set_nonblocking(true)?;
        socket6.set_reuse_address(true)?;

        socket4.bind(&SocketAddrV4::new(Ipv4Addr::unspecified(), port).into())?;
        socket6.bind(&SocketAddrV6::new(Ipv6Addr::unspecified(), port, 0, 0).into())?;

        let socket4 = mio::net::UdpSocket::from_socket(socket4.into_udp_socket())?;
        let socket6 = mio::net::UdpSocket::from_socket(socket6.into_udp_socket())?;

        let io4 = PollEvented::new(socket4, &handle)?;
        let io6 = PollEvented::new(socket6, &handle)?;
        Ok(UdpSocket { io4, io6, handle })
    }

    pub fn framed(self) -> UdpFramed {
        frame::new(self)
    }

    /// Returns the local address that this stream is bound to.
    pub fn local_addrs(&self) -> io::Result<(SocketAddr, SocketAddr)> {
        Ok((self.io4.get_ref().local_addr()?, self.io6.get_ref().local_addr()?))
    }

    fn get_io(&self, addr: &SocketAddr) -> &PollEvented<mio::net::UdpSocket> {
        match *addr {
            SocketAddr::V4(_) => &self.io4,
            SocketAddr::V6(_) => &self.io6,
        }
    }

    /// Test whether this socket is ready to be read or not.
    ///
    /// If the socket is *not* readable then the current task is scheduled to
    /// get a notification when the socket does become readable. That is, this
    /// is only suitable for calling in a `Future::poll` method and will
    /// automatically handle ensuring a retry once the socket is readable again.
    pub fn poll_read(&self) -> Async<()> {
        match self.io4.poll_read() {
            Async::NotReady => self.io6.poll_read(),
            res => res
        }
    }

    /// Test whether this socket is ready to be written to or not.
    ///
    /// If the socket is *not* writable then the current task is scheduled to
    /// get a notification when the socket does become writable. That is, this
    /// is only suitable for calling in a `Future::poll` method and will
    /// automatically handle ensuring a retry once the socket is writable again.
    pub fn poll_write(&self) -> Async<()> {
        match self.io4.poll_write() {
            Async::NotReady => self.io6.poll_write(),
            res => res
        }
    }

    /// Sends data on the socket to the given address. On success, returns the
    /// number of bytes written.
    ///
    /// Address type can be any implementer of `ToSocketAddrs` trait. See its
    /// documentation for concrete examples.
    pub fn send_to(&self, buf: &[u8], target: &SocketAddr) -> io::Result<usize> {
        let io = self.get_io(target);
        if let Async::NotReady = io.poll_write() {
            return Err(io::ErrorKind::WouldBlock.into())
        }

        match io.get_ref().send_to(buf, target) {
            Ok(n) => Ok(n),
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    io.need_write();
                }
                Err(e)
            }
        }
    }

    /// Receives data from the socket. On success, returns the number of bytes
    /// read and the address from whence the data came.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let io = match (self.io4.poll_read(), self.io6.poll_read()) {
            (Async::Ready(_), _) => &self.io4,
            (_, Async::Ready(_)) => &self.io6,
            _                    => return Err(io::ErrorKind::WouldBlock.into()),
        };

        let mut cmsgspace = CmsgSpace::<[u8; 1024]>::new();
        let res = recvmsg(io.get_ref().as_raw_fd(),
                          &[IoVec::from_mut_slice(buf)],
                          Some(&mut cmsgspace),
                          MsgFlags::empty());

        match res {
            Ok(msg) => {
                for cmsg in msg.cmsgs() {
                    match cmsg {
                        ControlMessage::Ipv4PacketInfo(info) => {
                            trace!("ipv4 cmsg (\n  ipi_addr: {:?},\n  ipi_spec_dst: {:?},\n  ipi_ifindex: {}\n)",
                                    Ipv4Addr::from(info.ipi_addr),
                                    Ipv4Addr::from(info.ipi_spec_dst),
                                    info.ipi_ifindex);
                        },
                        ControlMessage::Ipv6PacketInfo(info) => {
                            trace!("ipv6 cmsg (\n  ipi6_addr: {:?},\n  ipi6_ifindex: {}\n)",
                                    Ipv6Addr::from(info.ipi6_addr.s6_addr),
                                    info.ipi6_ifindex);
                        },
                        _ => trace!("unknown cmsg")
                    }
                }
                if let Some(SockAddr::Inet(addr)) = msg.address {
                    Ok((msg.bytes, addr.to_std()))
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "invalid source address"))
                }
            },
            Err(nix::Error::Sys(Errno::EAGAIN)) => {
                io.need_read();
                Err(io::ErrorKind::WouldBlock.into())
            },
            Err(nix::Error::Sys(errno)) => {
                Err(io::Error::last_os_error())
            },
            Err(e) => {
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }

    fn as_raw_fd_v4(&self) -> RawFd {
        self.io4.get_ref().as_raw_fd()
    }

    fn as_raw_fd_v6(&self) -> RawFd {
        self.io6.get_ref().as_raw_fd()
    }
}

