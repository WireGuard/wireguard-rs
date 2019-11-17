use super::super::bind::*;
use super::super::Endpoint;

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

#[derive(Clone)]
pub struct LinuxBind(Arc<UdpSocket>);

pub struct LinuxOwner(Arc<UdpSocket>);

impl Endpoint for SocketAddr {
    fn clear_src(&mut self) {}

    fn from_address(addr: SocketAddr) -> Self {
        addr
    }

    fn into_address(&self) -> SocketAddr {
        *self
    }
}

impl Reader<SocketAddr> for LinuxBind {
    type Error = io::Error;

    fn read(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), Self::Error> {
        self.0.recv_from(buf)
    }
}

impl Writer<SocketAddr> for LinuxBind {
    type Error = io::Error;

    fn write(&self, buf: &[u8], dst: &SocketAddr) -> Result<(), Self::Error> {
        self.0.send_to(buf, dst)?;
        Ok(())
    }
}

impl Owner for LinuxOwner {
    type Error = io::Error;

    fn get_port(&self) -> u16 {
        self.0.local_addr().unwrap().port() // todo handle
    }

    fn get_fwmark(&self) -> Option<u32> {
        None
    }

    fn set_fwmark(&mut self, _value: Option<u32>) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Drop for LinuxOwner {
    fn drop(&mut self) {}
}

impl Bind for LinuxBind {
    type Error = io::Error;
    type Endpoint = SocketAddr;
    type Reader = LinuxBind;
    type Writer = LinuxBind;
}

impl PlatformBind for LinuxBind {
    type Owner = LinuxOwner;

    fn bind(port: u16) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", port))?;
        let socket = Arc::new(socket);

        Ok((
            vec![LinuxBind(socket.clone())],
            LinuxBind(socket.clone()),
            LinuxOwner(socket),
        ))
    }
}
