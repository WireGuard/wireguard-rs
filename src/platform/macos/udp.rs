use super::super::udp::*;
use super::super::Endpoint;

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::RawFd;

use nix::sys::{
    socket::{
        bind, getsockname, recvmsg, sendmsg, setsockopt, socket,
        sockopt::{Ipv4RecvDstAddr, Ipv4RecvIf, Ipv6RecvPacketInfo, ReuseAddr, ReusePort},
        AddressFamily, ControlMessage, ControlMessageOwned, InetAddr, IpAddr, MsgFlags, SockAddr,
        SockFlag, SockProtocol, SockType,
    },
    uio::IoVec,
};
use std::sync::Arc;

#[derive(Debug)]
pub struct UdpSocket {
    socket: RawFd,
    is_ipv4: bool,
}

#[derive(Debug)]
pub enum UdpError {
    OpenSocket(nix::Error),
    SetSocketOpt(nix::Error),
    GetSockName(nix::Error),
    BindSocket(nix::Error),
    SendMsg(nix::Error),
    RecvMsg(nix::Error),
    UnexpectedControlMessage(ControlMessageOwned),
    NoControlMessage,
    InvalidAddress(Option<SockAddr>),
    UnsupportedProtocol(&'static str),
    InsufficientSourceInfo(Option<libc::in_addr>, Option<u32>),
}

impl std::fmt::Display for UdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use UdpError::*;
        match self {
            OpenSocket(err) => {
                write!(f, "failed to open socket: {}", err)
            }
            SetSocketOpt(err) => {
                write!(f, "failed to set socket option: {}", err)
            }
            GetSockName(err) => {
                write!(f, "failed to get socket name: {}", err)
            }
            BindSocket(err) => {
                write!(f, "failed to bind socket: {}", err)
            }
            SendMsg(err) => {
                write!(f, "failed to send message: {}", err)
            }
            RecvMsg(err) => {
                write!(f, "failed to receive message: {}", err)
            }
            InvalidAddress(Some(invalid_addr)) => {
                write!(f, "expected socket address, got {}", invalid_addr)
            }
            InvalidAddress(None) => {
                write!(f, "expected socket address")
            }
            UnexpectedControlMessage(unexpected_message) => {
                write!(
                    f,
                    "received unexpected control message: {:?}",
                    unexpected_message
                )
            }
            NoControlMessage => {
                write!(f, "received no control message")
            }
            UnsupportedProtocol(protocol) => {
                write!(f, "unsupported protocol {}", protocol)
            }
            InsufficientSourceInfo(in_addr, if_index) => {
                let mut faults = Vec::with_capacity(2);
                if in_addr.is_none() {
                    faults.push("no address")
                }
                if if_index.is_none() {
                    faults.push("no reciving interface index")
                }
                write!(f, "received packet with {}", faults.join(" and "))
            }
        }
    }
}

impl std::error::Error for UdpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use UdpError::*;
        match self {
            OpenSocket(err) | SetSocketOpt(err) | GetSockName(err) | BindSocket(err)
            | SendMsg(err) | RecvMsg(err) => Some(err),
            UnexpectedControlMessage(_)
            | NoControlMessage
            | InvalidAddress(_)
            | UnsupportedProtocol(_)
            | InsufficientSourceInfo(_, _) => None,
        }
    }
}

type Result<T> = std::result::Result<T, UdpError>;

impl UdpSocket {
    fn bind(addr: impl Into<std::net::IpAddr>, port: u16) -> Result<(u16, Self)> {
        let ip_addr = addr.into();
        let addr_family = if ip_addr.is_ipv4() {
            AddressFamily::Inet
        } else {
            AddressFamily::Inet6
        };
        let inet_addr = InetAddr::new(IpAddr::from_std(&ip_addr), port);
        let socket_addr = SockAddr::new_inet(inet_addr);

        let socket: RawFd = socket(
            addr_family,
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::Udp,
        )
        .map_err(UdpError::OpenSocket)?;

        if ip_addr.is_ipv4() {
            setsockopt(socket, Ipv4RecvDstAddr, &true).map_err(UdpError::SetSocketOpt)?;
            setsockopt(socket, Ipv4RecvIf, &true).map_err(UdpError::SetSocketOpt)?;
        } else {
            setsockopt(socket, Ipv6RecvPacketInfo, &true).map_err(UdpError::SetSocketOpt)?;
        }

        setsockopt(socket, ReuseAddr, &true).map_err(UdpError::SetSocketOpt)?;
        setsockopt(socket, ReusePort, &true).map_err(UdpError::SetSocketOpt)?;

        bind(socket, &socket_addr).map_err(UdpError::BindSocket)?;
        let bound_port = if port == 0 {
            let sockaddr = getsockname(socket).map_err(UdpError::GetSockName)?;
            Self::validate_sockaddr(Some(sockaddr))?.port()
        } else {
            port
        };

        Ok((
            bound_port,
            Self {
                socket,
                is_ipv4: ip_addr.is_ipv4(),
            },
        ))
    }

    fn validate_sockaddr(addr: Option<SockAddr>) -> Result<InetAddr> {
        match addr {
            Some(SockAddr::Inet(inet)) => Ok(inet),
            anything_else => Err(UdpError::InvalidAddress(anything_else)),
        }
    }

    fn send_to(&self, buf: &[u8], endpoint: &MacosEndpoint) -> Result<usize> {
        let iov = [IoVec::from_slice(buf)];
        let packet_info = PacketInfo::new(endpoint);
        let control_messages = [packet_info.control_message()];
        sendmsg(
            self.socket,
            &iov,
            &control_messages,
            MsgFlags::empty(),
            Some(&SockAddr::new_inet(endpoint.destination())),
        )
        .map_err(UdpError::SendMsg)
    }

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, MacosEndpoint)> {
        let iov = [IoVec::from_mut_slice(buf)];
        let mut control_messages_buffer = self.control_message_buffer();
        let msg = recvmsg(
            self.socket,
            &iov,
            Some(&mut control_messages_buffer),
            MsgFlags::empty(),
        )
        .map_err(UdpError::RecvMsg)?;

        let endpoint = if self.is_ipv4 {
            let mut destination_addr = None;
            let mut if_index = None;
            let src_addr_info = match msg.address {
                Some(SockAddr::Inet(InetAddr::V4(sockaddr_in))) => sockaddr_in,
                anything_else => {
                    return Err(UdpError::InvalidAddress(anything_else));
                }
            };
            let control_messages = msg.cmsgs();
            for message in control_messages {
                match message {
                    ControlMessageOwned::Ipv4RecvIf(if_sockaddr) => {
                        if_index = Some(if_sockaddr.sdl_index as u32);
                    }
                    ControlMessageOwned::Ipv4RecvDstAddr(in_addr) => {
                        destination_addr = Some(in_addr);
                    }
                    other => {
                        log::error!("received unexpected control message: {:?}", other);
                        continue;
                    }
                }
            }
            match (destination_addr, if_index) {
                (Some(incoming_destination), Some(src_if_index)) => MacosEndpoint::V4 {
                    destination: src_addr_info,
                    src_if_index: src_if_index,
                    src_addr: incoming_destination,
                },
                (dest, if_index) => {
                    return Err(UdpError::InsufficientSourceInfo(dest, if_index));
                }
            }
        } else {
            let src_addr_info = match msg.address {
                Some(SockAddr::Inet(InetAddr::V6(inet_addr))) => inet_addr,
                anything_else => {
                    return Err(UdpError::InvalidAddress(anything_else));
                }
            };

            let src_if_index = match msg.cmsgs().next() {
                Some(ControlMessageOwned::Ipv6PacketInfo(packet_info)) => packet_info.ipi6_ifindex,
                Some(any_other_cmsg) => {
                    return Err(UdpError::UnexpectedControlMessage(any_other_cmsg));
                }
                None => {
                    return Err(UdpError::NoControlMessage);
                }
            };
            MacosEndpoint::V6 {
                destination: src_addr_info,
                src_if_index,
            }
        };
        Ok((msg.bytes, endpoint))
    }

    fn control_message_buffer(&self) -> Vec<u8> {
        if self.is_ipv4 {
            nix::cmsg_space![libc::in_addr, libc::sockaddr_dl]
        } else {
            nix::cmsg_space![libc::in6_pktinfo]
        }
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        log::debug!("macos udp, release fd (fd = {})", self.socket);
        if let Err(err) = nix::unistd::close(self.socket) {
            log::error!("failed to close UdpSocket {}", err);
        }
    }
}
enum PacketInfo {
    V4(libc::in_pktinfo),
    V6(libc::in6_pktinfo),
}

impl PacketInfo {
    fn new(endpoint: &MacosEndpoint) -> Self {
        match endpoint {
            MacosEndpoint::V4 {
                destination,
                src_if_index,
                src_addr,
            } => Self::V4(libc::in_pktinfo {
                ipi_addr: destination.sin_addr,
                ipi_ifindex: *src_if_index,
                ipi_spec_dst: *src_addr,
            }),
            MacosEndpoint::V6 {
                destination,
                src_if_index,
            } => Self::V6(libc::in6_pktinfo {
                ipi6_addr: destination.sin6_addr,
                ipi6_ifindex: *src_if_index,
            }),
        }
    }

    fn control_message<'a>(&'a self) -> ControlMessage<'a> {
        match self {
            Self::V4(v4) => ControlMessage::Ipv4PacketInfo(v4),
            Self::V6(v6) => ControlMessage::Ipv6PacketInfo(v6),
        }
    }
}

pub struct MacosUDP();

pub struct MacosOwner {
    port: u16,
    _sock4: Option<Arc<UdpSocket>>,
    _sock6: Option<Arc<UdpSocket>>,
}

impl Owner for MacosOwner {
    type Error = UdpError;

    fn get_port(&self) -> u16 {
        self.port
    }

    fn set_fwmark(&mut self, _value: Option<u32>) -> Result<()> {
        Ok(())
    }
}

pub enum MacosUDPReader {
    V4(Arc<UdpSocket>),
    V6(Arc<UdpSocket>),
}

impl AsRef<UdpSocket> for MacosUDPReader {
    fn as_ref(&self) -> &UdpSocket {
        match self {
            Self::V4(socket) | Self::V6(socket) => &*socket,
        }
    }
}

#[derive(Clone)]
pub struct MacosUDPWriter {
    sock4: Option<Arc<UdpSocket>>,
    sock6: Option<Arc<UdpSocket>>,
}

#[derive(Debug)]
pub enum MacosEndpoint {
    V4 {
        destination: libc::sockaddr_in,
        src_if_index: u32,
        src_addr: libc::in_addr,
    },
    V6 {
        destination: libc::sockaddr_in6,
        src_if_index: u32,
    },
}

impl MacosEndpoint {
    fn destination(&self) -> InetAddr {
        match self {
            Self::V4 { destination, .. } => InetAddr::V4(*destination),
            Self::V6 { destination, .. } => InetAddr::V6(*destination),
        }
    }
    fn is_ipv4(&self) -> bool {
        match self {
            Self::V4 { .. } => true,
            Self::V6 { .. } => false,
        }
    }
}

impl Endpoint for MacosEndpoint {
    fn from_address(addr: SocketAddr) -> Self {
        let sock_addr = InetAddr::from_std(&addr);
        match sock_addr {
            InetAddr::V4(destination) => Self::V4 {
                destination,
                src_if_index: 0,
                src_addr: libc::in_addr { s_addr: 0u32 },
            },
            InetAddr::V6(destination) => Self::V6 {
                destination,
                src_if_index: 0,
            },
        }
    }

    fn clear_src(&mut self) {
        match self {
            Self::V4 {
                ref mut src_if_index,
                ref mut src_addr,
                ..
            } => {
                *src_if_index = 0;
                *src_addr = libc::in_addr { s_addr: 0u32 };
            }
            Self::V6 {
                ref mut src_if_index,
                ..
            } => {
                *src_if_index = 0;
            }
        }
    }

    fn into_address(&self) -> SocketAddr {
        self.destination().to_std()
    }
}

impl Reader<MacosEndpoint> for MacosUDPReader {
    type Error = UdpError;

    fn read(&self, buf: &mut [u8]) -> Result<(usize, MacosEndpoint)> {
        self.as_ref().recv_from(buf)
    }
}

impl Writer<MacosEndpoint> for MacosUDPWriter {
    type Error = UdpError;

    fn write(&self, buf: &[u8], dst: &mut MacosEndpoint) -> Result<()> {
        let maybe_socket = if dst.is_ipv4() {
            &self.sock4
        } else {
            &self.sock6
        };

        let socket =
            maybe_socket
                .as_ref()
                .ok_or(UdpError::UnsupportedProtocol(if dst.is_ipv4() {
                    "ipv4"
                } else {
                    "ipv6"
                }))?;

        let _ = socket.send_to(buf, dst)?;
        Ok(())
    }
}

impl UDP for MacosUDP {
    type Error = UdpError;
    type Endpoint = MacosEndpoint;
    type Writer = MacosUDPWriter;
    type Reader = MacosUDPReader;
}

impl MacosUDP {}

impl PlatformUDP for MacosUDP {
    type Owner = MacosOwner;

    #[allow(clippy::type_complexity)]
    #[allow(clippy::unnecessary_unwrap)]
    fn bind(mut port: u16) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner)> {
        log::trace!("binding to port {}", port);

        let bind6 = UdpSocket::bind(Ipv6Addr::UNSPECIFIED, port);
        if let Ok((new_port, _)) = bind6 {
            port = new_port;
        }

        let bind4 = UdpSocket::bind(Ipv4Addr::UNSPECIFIED, port);
        if let Ok((new_port, _)) = bind4 {
            port = new_port;
        }

        if bind4.is_err() && bind6.is_err() {
            log::trace!("failed to bind for either IP version");
            return Err(bind6.unwrap_err());
        }

        let sock6 = bind6.ok().map(|(_, socket)| Arc::new(socket));
        let sock4 = bind4.ok().map(|(_, socket)| Arc::new(socket));

        let owner = MacosOwner {
            port,
            _sock6: sock6.clone(),
            _sock4: sock4.clone(),
        };

        let mut readers: Vec<Self::Reader> = Vec::with_capacity(2);
        if let Some(sock) = sock6.clone() {
            readers.push(MacosUDPReader::V6(sock))
        }
        if let Some(sock) = sock4.clone() {
            readers.push(MacosUDPReader::V4(sock))
        }
        debug_assert!(!readers.is_empty());

        let writer = MacosUDPWriter { sock4, sock6 };

        Ok((readers, writer, owner))
    }
}
