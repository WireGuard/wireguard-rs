use std::io;
use std::net::{SocketAddr, Ipv4Addr, SocketAddrV4, IpAddr};
use std::os::unix::io::{AsRawFd, RawFd};

use failure::Error;
use futures::{Async, Future, Poll, Stream, Sink, StartSend, AsyncSink, future, stream, unsync::mpsc};
use nix::sys::socket::{sockopt, setsockopt};
use udp::{ConnectedUdpSocket, UdpSocket};
use tokio_core::reactor::Handle;
use std::net::Ipv6Addr;

pub enum Socket {
    Unconnected(UdpSocket),
    Connected(ConnectedUdpSocket),
}

/// A unified `Stream` and `Sink` interface to an underlying `UdpSocket`, using
/// the `UdpCodec` trait to encode and decode frames.
///
/// You can acquire a `UdpFramed` instance by using the `UdpSocket::framed`
/// adapter.
#[must_use = "sinks do nothing unless polled"]
pub struct UdpFramed {
    socket: Socket,
    codec: VecUdpCodec,
    rd: Vec<u8>,
    wr: Vec<u8>,
    out_addr: SocketAddr,
    flushed: bool,
}

impl UdpFramed {
    pub fn socket(&self) -> &UdpSocket {
        match self.socket {
            Socket::Unconnected(ref socket) => socket,
            Socket::Connected(ref socket) => &socket.inner,
        }
    }
}

impl Stream for UdpFramed {
    type Item = PeerServerMessage;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<PeerServerMessage>, io::Error> {
        let (n, addr) = match self.socket {
            Socket::Unconnected(ref socket) => try_nb!(socket.recv_from(&mut self.rd)),
            Socket::Connected(ref socket)   => (try_nb!(socket.inner.recv(&mut self.rd)), socket.addr),
        };
        trace!("received {} bytes, decoding", n);
        let frame = self.codec.decode(&addr, &self.rd[..n])?;
        trace!("frame decoded from buffer");
        Ok(Async::Ready(Some(frame)))
    }
}

impl Sink for UdpFramed {
    type SinkItem = PeerServerMessage;
    type SinkError = io::Error;

    fn start_send(&mut self, item: PeerServerMessage) -> StartSend<PeerServerMessage, io::Error> {
        trace!("sending frame");

        if !self.flushed {
            match self.poll_complete()? {
                Async::Ready(()) => {},
                Async::NotReady => return Ok(AsyncSink::NotReady(item)),
            }
        }

        self.out_addr = self.codec.encode(item, &mut self.wr);
        self.flushed = false;
        trace!("frame encoded; length={}", self.wr.len());

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        if self.flushed {
            return Ok(Async::Ready(()))
        }

        trace!("flushing frame; length={}", self.wr.len());
        let n = match self.socket {
            Socket::Unconnected(ref socket) => try_nb!(socket.send_to(&self.wr, &self.out_addr)),
            Socket::Connected(ref socket)   => try_nb!(socket.inner.send(&self.wr)) // TODO check to make sure the address is the connected address
        };
        trace!("written {}", n);

        let wrote_all = n == self.wr.len();
        self.wr.clear();
        self.flushed = true;

        if wrote_all {
            Ok(Async::Ready(()))
        } else {
            Err(io::Error::new(io::ErrorKind::Other,
                               "failed to write entire datagram to socket"))
        }
    }

    fn close(&mut self) -> Poll<(), io::Error> {
        try_ready!(self.poll_complete());
        Ok(().into())
    }
}

pub fn new(socket: Socket) -> UdpFramed {
    UdpFramed {
        socket,
        codec: VecUdpCodec {},
        out_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
        rd: vec![0; 64 * 1024],
        wr: Vec::with_capacity(8 * 1024),
        flushed: true,
    }
}

impl UdpFramed {
    /// Returns a reference to the underlying I/O stream wrapped by `Framed`.
    ///
    /// Note that care should be taken to not tamper with the underlying stream
    /// of data coming in as it may corrupt the stream of frames otherwise being
    /// worked with.
    pub fn get_ref(&self) -> &UdpSocket {
        match self.socket {
            Socket::Connected(ref socket) => &socket.inner,
            Socket::Unconnected(ref socket) => socket
        }
    }

    /// Returns a mutable reference to the underlying I/O stream wrapped by
    /// `Framed`.
    ///
    /// Note that care should be taken to not tamper with the underlying stream
    /// of data coming in as it may corrupt the stream of frames otherwise being
    /// worked with.
    pub fn get_mut(&mut self) -> &mut UdpSocket {
        match self.socket {
            Socket::Connected(ref mut socket) => &mut socket.inner,
            Socket::Unconnected(ref mut socket) => socket
        }
    }

    /// Consumes the `Framed`, returning its underlying I/O stream.
    ///
    /// Note that care should be taken to not tamper with the underlying stream
    /// of data coming in as it may corrupt the stream of frames otherwise being
    /// worked with.
    pub fn into_inner(self) -> UdpSocket {
        match self.socket {
            Socket::Connected(socket) => socket.inner,
            Socket::Unconnected(socket) => socket
        }
    }
}

fn v6_mapped_to_v4(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    match addr.segments() {
        [0, 0, 0, 0, 0, f, g, h] if f == 0xffff => {
            Some(Ipv4Addr::new((g >> 8) as u8, g as u8,
                               (h >> 8) as u8, h as u8))
        },
        _ => None
    }
}

pub type PeerServerMessage = (SocketAddr, Vec<u8>);
pub struct VecUdpCodec;
impl VecUdpCodec {
    fn decode(&mut self, src: &SocketAddr, buf: &[u8]) -> io::Result<PeerServerMessage> {
        let unmapped_ip = match src.ip() {
            IpAddr::V6(v6addr) => {
                if let Some(v4addr) = v6_mapped_to_v4(v6addr) {
                    IpAddr::V4(v4addr)
                } else {
                    IpAddr::V6(v6addr)
                }
            }
            v4addr => v4addr
        };
        Ok((SocketAddr::new(unmapped_ip, src.port()), buf.to_vec()))
    }

    fn encode(&mut self, msg: PeerServerMessage, buf: &mut Vec<u8>) -> SocketAddr {
        let (mut addr, mut data) = msg;
        buf.append(&mut data);
        let mapped_ip = match addr.ip() {
            IpAddr::V4(v4addr) => IpAddr::V6(v4addr.to_ipv6_mapped()),
            v6addr => v6addr
        };
        addr.set_ip(mapped_ip);
        addr
    }
}

pub struct UdpChannel {
    pub ingress : stream::SplitStream<UdpFramed>,
    pub egress  : mpsc::Sender<PeerServerMessage>,
    pub fd      : RawFd,
        handle  : Handle,
}

impl From<UdpFramed> for UdpChannel {
    fn from(framed: UdpFramed) -> Self {
        let fd = framed.socket().as_raw_fd();
        let handle = framed.socket().handle.clone();
        let (udp_sink, ingress) = framed.split();
        let (egress, egress_rx) = mpsc::channel(1024);
        let udp_writethrough    = udp_sink
            .sink_map_err(|_| ())
            .send_all(egress_rx.and_then(|(addr, packet)| {
                          trace!("sending UDP packet to {:?}", &addr);
                          future::ok((addr, packet))
                      })
                      .map_err(|_| { info!("udp sink error"); () }))
            .then(|_| Ok(()));

        handle.spawn(udp_writethrough);

        UdpChannel { egress, ingress, fd, handle }
    }
}

impl UdpChannel {
    pub fn send(&self, message: PeerServerMessage) {
        self.handle.spawn(self.egress.clone().send(message).then(|_| Ok(())));
    }

    #[cfg(target_os = "linux")]
    pub fn set_mark(&self, mark: u32) -> Result<(), Error> {
        Ok(setsockopt(self.fd, sockopt::Mark, &mark)?)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn set_mark(&self, _mark: u32) -> Result<(), Error> {
        Ok(())
    }
}
