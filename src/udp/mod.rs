#![allow(unused)]

use std::{fmt, io, mem};
use std::net::{self, SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, RawFd};

use futures::{Async, Future, Poll};
use libc;
use mio;
use nix::{self, errno::Errno};
use nix::sys::{uio::IoVec,
               socket::{
                   in6_pktinfo,
                   in_pktinfo,
                   CmsgSpace,
                   ControlMessage,
                   InetAddr,
                   UnknownCmsg,
                   MsgFlags,
                   SockAddr,
                   recvmsg,
                   sendmsg,
                   setsockopt,
                   sockopt
               }};
use socket2::{Socket, Domain, Type, Protocol};

use tokio_core::reactor::{Handle, PollEvented};

mod frame;
pub use self::frame::{UdpChannel, UdpFramed, VecUdpCodec, PeerServerMessage};
use std::ops::Deref;

/// An I/O object representing a UDP socket.
pub struct UdpSocket {
    io4: PollEvented<mio::net::UdpSocket>,
    io6: PollEvented<mio::net::UdpSocket>,
    handle: Handle,
}

// I understand that, ex., the V4 enum should really hold a SocketAddrV4 struct,
// but this is for simplicity because nix only offers a to_std() that returns
// `SocketAddr` from its `SockAddr`, so it makes the code cleaner with little
// performance impact.
#[derive(Clone, Copy, Debug)]
pub enum Endpoint {
    V4(SocketAddr, Option<in_pktinfo>),
    V6(SocketAddr, Option<in6_pktinfo>)
}

impl Endpoint {
    fn addr(&self) -> SocketAddr {
        match *self {
            Endpoint::V4(sock, _) => sock,
            Endpoint::V6(sock, _) => sock,
        }
    }
}

impl Deref for Endpoint {
    type Target = SocketAddr;

    fn deref(&self) -> &<Self as Deref>::Target {
        match *self {
            Endpoint::V4(ref sock, _) => sock,
            Endpoint::V6(ref sock, _) => sock
        }
    }
}

impl From<SocketAddr> for Endpoint {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(_) => Endpoint::V4(addr, None),
            SocketAddr::V6(_) => Endpoint::V6(addr, None),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum PktInfo {
    V4(in_pktinfo),
    V6(in6_pktinfo),
}

impl UdpSocket {
    pub fn bind(port: u16, handle: Handle) -> io::Result<UdpSocket> {
        let socket4 = Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp()))?;
        let socket6 = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp()))?;

        socket4.set_nonblocking(true)?;
        socket4.set_reuse_address(true)?;

        socket6.set_nonblocking(true)?;
        socket6.set_reuse_address(true)?;
        socket6.set_only_v6(true)?;

        setsockopt(socket4.as_raw_fd(), sockopt::Ipv4PacketInfo, &true);
        setsockopt(socket6.as_raw_fd(), sockopt::Ipv6RecvPacketInfo, &true);

        socket4.bind(&SocketAddr::from((Ipv4Addr::unspecified(), port)).into())?;
        socket6.bind(&SocketAddr::from((Ipv6Addr::unspecified(), port)).into())?;

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

    fn get_io(&self, endpoint: &Endpoint) -> &PollEvented<mio::net::UdpSocket> {
        match *endpoint {
            Endpoint::V4(..) => &self.io4,
            Endpoint::V6(..) => &self.io6,
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
    pub fn send_to(&self, buf: &[u8], target: &Endpoint) -> io::Result<usize> {
        let io = self.get_io(target);
        if let Async::NotReady = io.poll_write() {
            return Err(io::ErrorKind::WouldBlock.into())
        }

        let cmsgs = match *target {
            Endpoint::V4(addr, Some(ref pktinfo)) => vec![ControlMessage::Ipv4PacketInfo(pktinfo)],
            Endpoint::V6(addr, Some(ref pktinfo)) => vec![ControlMessage::Ipv6PacketInfo(pktinfo)],
            _                                     => vec![]
        };

        match *target {
            Endpoint::V4(addr, Some(ref pktinfo)) => trace!("sending cmsg: {:?}", pktinfo),
            Endpoint::V6(addr, Some(ref pktinfo)) => trace!("sending cmsg: {:?}", pktinfo),
            _                                     => trace!("not sending any pktinfo")
        }

        let res = sendmsg(io.get_ref().as_raw_fd(),
                          &[IoVec::from_slice(buf)],
                          &cmsgs,
                          MsgFlags::empty(),
                          Some(&SockAddr::Inet(InetAddr::from_std(&target.addr()))));

        match res {
            Ok(len) => Ok(len),
            Err(nix::Error::Sys(Errno::EAGAIN)) => {
                io.need_write();
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

    /// Receives data from the socket. On success, returns the number of bytes
    /// read and the address from whence the data came.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Endpoint)> {
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
                if let Some(SockAddr::Inet(addr)) = msg.address {
                    match msg.cmsgs().next() {
                        Some(ControlMessage::Ipv4PacketInfo(info)) => {
                            trace!("ipv4 cmsg (\n  ipi_addr: {:?},\n  ipi_spec_dst: {:?},\n  ipi_ifindex: {}\n)",
                                   Ipv4Addr::from(info.ipi_addr),
                                   Ipv4Addr::from(info.ipi_spec_dst),
                                   info.ipi_ifindex);
                            let endpoint = Endpoint::V4(addr.to_std(), Some(in_pktinfo {
                                ipi_addr    : [0u8; 4],
                                ipi_spec_dst: info.ipi_addr,
                                ipi_ifindex : info.ipi_ifindex,
                            }));
                            Ok((msg.bytes, endpoint))
                        },
                        Some(ControlMessage::Ipv6PacketInfo(info)) => {
                            trace!("ipv6 cmsg (\n  ipi6_addr: {:?},\n  ipi6_ifindex: {}\n)",
                                   Ipv6Addr::from(info.ipi6_addr),
                                   info.ipi6_ifindex);
                            let endpoint = Endpoint::V6(addr.to_std(), Some(*info));
                            Ok((msg.bytes, endpoint))
                        },
                        _ => Err(io::Error::new(io::ErrorKind::Other, "missing pktinfo"))
                    }
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

