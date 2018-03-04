#![allow(unused)]

use std::io;
use std::net::{self, SocketAddr, Ipv4Addr, Ipv6Addr};
use std::fmt;

use futures::{Async, Future, Poll};
use mio;
use socket2::{Socket, Domain, Type, Protocol};

use tokio_core::reactor::{Handle, PollEvented};

/// An I/O object representing a UDP socket.
pub struct UdpSocket {
    io: PollEvented<mio::net::UdpSocket>,
    handle: Handle,
}

mod frame;
pub use self::frame::{UdpChannel, UdpFramed, VecUdpCodec, PeerServerMessage};

pub struct ConnectedUdpSocket {
    inner: UdpSocket,
    addr: SocketAddr,
}

impl ConnectedUdpSocket {
    pub fn framed(self) -> UdpFramed {
        frame::new(frame::Socket::Connected(self))
    }
}

impl UdpSocket {
    /// Create a new UDP socket bound to the specified address.
    ///
    /// This function will create a new UDP socket and attempt to bind it to the
    /// `addr` provided. If the result is `Ok`, the socket has successfully bound.
    pub fn bind(addr: SocketAddr, handle: Handle) -> io::Result<UdpSocket> {
        let socket = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp()))?;
        socket.set_only_v6(false)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_port(true)?;
        socket.bind(&addr.into())?;
        Self::from_socket(socket.into_udp_socket(), handle)
    }

    fn new(socket: mio::net::UdpSocket, handle: Handle) -> io::Result<UdpSocket> {
        let io = PollEvented::new(socket, &handle)?;
        Ok(UdpSocket { io, handle })
    }

    /// Creates a new `UdpSocket` from the previously bound socket provided.
    ///
    /// The socket given will be registered with the event loop that `handle` is
    /// associated with. This function requires that `socket` has previously
    /// been bound to an address to work correctly.
    ///
    /// This can be used in conjunction with net2's `UdpBuilder` interface to
    /// configure a socket before it's handed off, such as setting options like
    /// `reuse_address` or binding to multiple addresses.
    pub fn from_socket(socket: net::UdpSocket,
                       handle: Handle) -> io::Result<UdpSocket> {
        let udp = mio::net::UdpSocket::from_socket(socket)?;
        UdpSocket::new(udp, handle)
    }

    /// Provides a `Stream` and `Sink` interface for reading and writing to this
    /// `UdpSocket` object, using the provided `UdpCodec` to read and write the
    /// raw data.
    ///
    /// Raw UDP sockets work with datagrams, but higher-level code usually
    /// wants to batch these into meaningful chunks, called "frames". This
    /// method layers framing on top of this socket by using the `UdpCodec`
    /// trait to handle encoding and decoding of messages frames. Note that
    /// the incoming and outgoing frame types may be distinct.
    ///
    /// This function returns a *single* object that is both `Stream` and
    /// `Sink`; grouping this into a single object is often useful for layering
    /// things which require both read and write access to the underlying
    /// object.
    ///
    /// If you want to work more directly with the streams and sink, consider
    /// calling `split` on the `UdpFramed` returned by this method, which will
    /// break them into separate objects, allowing them to interact more
    /// easily.
    pub fn framed(self) -> UdpFramed {
        frame::new(frame::Socket::Unconnected(self))
    }

    /// Returns the local address that this stream is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.get_ref().local_addr()
    }

    /// Connects the UDP socket setting the default destination for send() and
    /// limiting packets that are read via recv from the address specified in addr.
    pub fn connect(self, addr: &SocketAddr) -> io::Result<ConnectedUdpSocket> {
        self.io.get_ref().connect(*addr)?;
        Ok(ConnectedUdpSocket{ inner: self, addr: *addr })
    }

    /// Sends data on the socket to the address previously bound via connect().
    /// On success, returns the number of bytes written.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        if let Async::NotReady = self.io.poll_write() {
            return Err(io::ErrorKind::WouldBlock.into())
        }
        match self.io.get_ref().send(buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.io.need_write();
                }
                Err(e)
            }
        }
    }

    /// Receives data from the socket previously bound with connect().
    /// On success, returns the number of bytes read.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        if let Async::NotReady = self.io.poll_read() {
            return Err(io::ErrorKind::WouldBlock.into())
        }
        match self.io.get_ref().recv(buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.io.need_read();
                }
                Err(e)
            }
        }
    }

    /// Test whether this socket is ready to be read or not.
    ///
    /// If the socket is *not* readable then the current task is scheduled to
    /// get a notification when the socket does become readable. That is, this
    /// is only suitable for calling in a `Future::poll` method and will
    /// automatically handle ensuring a retry once the socket is readable again.
    pub fn poll_read(&self) -> Async<()> {
        self.io.poll_read()
    }

    /// Test whether this socket is ready to be written to or not.
    ///
    /// If the socket is *not* writable then the current task is scheduled to
    /// get a notification when the socket does become writable. That is, this
    /// is only suitable for calling in a `Future::poll` method and will
    /// automatically handle ensuring a retry once the socket is writable again.
    pub fn poll_write(&self) -> Async<()> {
        self.io.poll_write()
    }

    /// Sends data on the socket to the given address. On success, returns the
    /// number of bytes written.
    ///
    /// Address type can be any implementer of `ToSocketAddrs` trait. See its
    /// documentation for concrete examples.
    pub fn send_to(&self, buf: &[u8], target: &SocketAddr) -> io::Result<usize> {
        if let Async::NotReady = self.io.poll_write() {
            return Err(io::ErrorKind::WouldBlock.into())
        }
        match self.io.get_ref().send_to(buf, target) {
            Ok(n) => Ok(n),
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.io.need_write();
                }
                Err(e)
            }
        }
    }

    /// Receives data from the socket. On success, returns the number of bytes
    /// read and the address from whence the data came.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        if let Async::NotReady = self.io.poll_read() {
            return Err(io::ErrorKind::WouldBlock.into())
        }
        match self.io.get_ref().recv_from(buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.io.need_read();
                }
                Err(e)
            }
        }
    }
}

impl fmt::Debug for UdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.io.get_ref().fmt(f)
    }
}

#[cfg(all(unix, not(target_os = "fuchsia")))]
mod sys {
    use std::os::unix::prelude::*;
    use super::UdpSocket;

    impl AsRawFd for UdpSocket {
        fn as_raw_fd(&self) -> RawFd {
            self.io.get_ref().as_raw_fd()
        }
    }
}

#[cfg(windows)]
mod sys {
    // TODO: let's land these upstream with mio and then we can add them here.
    //
    // use std::os::windows::prelude::*;
    // use super::UdpSocket;
    //
    // impl AsRawHandle for UdpSocket {
    //     fn as_raw_handle(&self) -> RawHandle {
    //         self.io.get_ref().as_raw_handle()
    //     }
    // }
}