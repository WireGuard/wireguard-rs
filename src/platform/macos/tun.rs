use crate::{
    plt::{fd::Fd, sys::*},
    tun::*,
};
use std::{
    fmt,
    fs::File,
    io::{self, Read, Write},
    mem,
    os::unix::io::FromRawFd,
};

pub const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";

use libc::{socklen_t, IFNAMSIZ};

#[derive(Debug)]
pub enum MacosTunError {
    InvalidName,
    Open(io::Error),
    CtliocginfoError(io::Error),
    Connect(io::Error),
    GetName(io::Error),
    TunStatusError(StatusError),
}

impl MacosTunError {
    fn last_os_error(kind: impl Fn(io::Error) -> Self) -> Self {
        kind(io::Error::last_os_error())
    }
}

impl fmt::Display for MacosTunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use MacosTunError::*;
        match self {
            InvalidName => write!(f, "Interface name must be utun[0-9]*"),
            Open(err) => write!(f, "failed to open tunnel socket: {}", err),
            CtliocginfoError(err) => write!(f, "failed configure socket for utun: {}", err),
            Connect(err) => write!(f, "failed to connect tunnel socket: {}", err),
            GetName(err) => write!(f, "failed to get tunnel name: {}", err),
            TunStatusError(err) => write!(f, "failed to create tunnel status reader: {}", err),
        }
    }
}

impl std::error::Error for MacosTunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use MacosTunError::*;
        match self {
            Open(err) | CtliocginfoError(err) | Connect(err) | GetName(err) => Some(err),
            TunStatusError(err) => Some(err),
            InvalidName => None,
        }
    }
}

impl From<StatusError> for MacosTunError {
    fn from(err: StatusError) -> Self {
        Self::TunStatusError(err)
    }
}

#[derive(Debug)]
pub enum StatusError {
    GetInterfaceIndex(io::Error),
    Open(io::Error),
    Read(io::Error),
}

impl StatusError {
    fn last_os_error(kind: impl Fn(io::Error) -> Self) -> Self {
        kind(io::Error::last_os_error())
    }
}

impl fmt::Display for StatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use StatusError::*;
        match self {
            GetInterfaceIndex(err) => {
                write!(f, "failed to get interface index: {}", err)
            }
            Open(err) => {
                write!(f, "failed to open route socket: {}", err)
            }
            Read(err) => {
                write!(f, "failed to read from route socket: {}", err)
            }
        }
    }
}

impl std::error::Error for StatusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use StatusError::*;
        match self {
            GetInterfaceIndex(err) | Open(err) | Read(err) => Some(err),
        }
    }
}

pub struct MacosTun {}

pub struct MacosTunStatus {
    interface_index: u32,
    route_socket: File,
}

impl MacosTunStatus {
    fn new(interface_name: [u8; libc::IFNAMSIZ]) -> Result<Self, StatusError> {
        let interface_index = unsafe { libc::if_nametoindex(interface_name.as_ptr() as _) };
        if interface_index == 0 {
            return Err(StatusError::last_os_error(StatusError::GetInterfaceIndex));
        }
        let route_socket_fd =
            unsafe { libc::socket(libc::AF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
        if route_socket_fd < 0 {
            return Err(StatusError::last_os_error(StatusError::Open));
        }
        let route_socket = unsafe { File::from_raw_fd(route_socket_fd) };

        Ok(Self {
            interface_index,
            route_socket,
        })
    }
}
impl Status for MacosTunStatus {
    type Error = StatusError;

    fn event(&mut self) -> Result<TunEvent, Self::Error> {
        let mut buffer = vec![0u8; page_size::get()];
        loop {
            let route_read = self.route_socket.read(buffer.as_mut_slice());
            let bytes_read = match route_read {
                Ok(bytes_read) => bytes_read,
                Err(err) => {
                    if err.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(StatusError::Read(err));
                }
            };

            if bytes_read < mem::size_of::<rt_msghdr>()
                || bytes_read < mem::size_of::<libc::if_msghdr>()
            {
                continue;
            }
            let msg_header: &rt_msghdr = unsafe { &*(buffer.as_ptr() as *const rt_msghdr) };
            if msg_header.rtm_type != libc::RTM_IFINFO as u8 {
                continue;
            }

            let if_msg: &libc::if_msghdr = unsafe { &*(buffer.as_ptr() as *const libc::if_msghdr) };
            if if_msg.ifm_index as u32 != self.interface_index {
                continue;
            }
            if if_msg.ifm_flags & libc::IFF_UP == 0 {
                return Ok(TunEvent::Down);
            }
            let mtu = if_msg.ifm_data.ifi_mtu;
            return Ok(TunEvent::Up(mtu as usize));
        }
    }
}
pub struct MacosTunWriter {
    tun: Fd,
}

impl Writer for MacosTunWriter {
    type Error = io::Error;
    fn write(&self, src: &[u8]) -> Result<(), Self::Error> {
        let mut buf = vec![0u8; src.len() + 4];
        buf[0] = 0x00;
        buf[1] = 0x00;
        buf[2] = 0x00;

        if src[0] >> 4 == 6 {
            buf[3] = libc::AF_INET6 as u8;
        } else {
            buf[3] = libc::AF_INET as u8;
        }
        buf[4..].copy_from_slice(src);

        let _ = self.tun.write(&buf)?;
        Ok(())
    }
}
pub struct MacosTunReader {
    tun: Fd,
}

impl Reader for MacosTunReader {
    type Error = io::Error;

    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Self::Error> {
        let bytes_read = self.tun.read(&mut buf[(offset.saturating_sub(4))..])?;
        if bytes_read < 4 {
            return Ok(0);
        }
        Ok(bytes_read - 4)
    }
}

impl Tun for MacosTun {
    type Writer = MacosTunWriter;
    type Reader = MacosTunReader;
    type Error = MacosTunError;
}

impl PlatformTun for MacosTun {
    type Status = MacosTunStatus;

    fn create(name: &str) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Status), Self::Error> {
        if name.as_bytes().len() > IFNAMSIZ {
            return Err(MacosTunError::InvalidName);
        }
        let name_index: u32 = name
            .strip_prefix("utun")
            .and_then(|index| index.parse().ok())
            .ok_or(MacosTunError::InvalidName)?;

        let tun_fd =
            unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if tun_fd < 0 {
            return Err(MacosTunError::last_os_error(MacosTunError::Open));
        }
        let tun = Fd::new(tun_fd);

        let mut info = ctl_info {
            ctl_id: 0,
            ctl_name: [0; 96],
        };
        (&mut info.ctl_name[..])
            .write(UTUN_CONTROL_NAME)
            .expect("failed to control name into ctl_info buffer");

        if unsafe { ctliocginfo(tun.raw_fd(), &mut info as *mut _ as *mut _) } < 0 {
            return Err(MacosTunError::last_os_error(
                MacosTunError::CtliocginfoError,
            ));
        }

        let addr = libc::sockaddr_ctl {
            sc_id: info.ctl_id,
            sc_len: mem::size_of::<libc::sockaddr_ctl>() as _,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_unit: name_index + 1,
            sc_reserved: [0; 5],
        };

        if unsafe {
            libc::connect(
                tun.raw_fd(),
                &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ctl>() as socklen_t,
            )
        } < 0
        {
            return Err(MacosTunError::last_os_error(MacosTunError::Connect));
        }

        let mut interface_name = [0u8; libc::IFNAMSIZ];
        let mut name_len: socklen_t = libc::IFNAMSIZ as u32;

        if unsafe {
            libc::getsockopt(
                tun.raw_fd(),
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                interface_name.as_mut_ptr() as *mut libc::c_void,
                &mut name_len as *mut socklen_t,
            )
        } < 0
        {
            return Err(MacosTunError::last_os_error(MacosTunError::GetName));
        }

        Ok((
            vec![MacosTunReader { tun: tun.clone() }],
            MacosTunWriter { tun },
            MacosTunStatus::new(interface_name)?,
        ))
    }
}
