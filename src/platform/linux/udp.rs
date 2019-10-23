use super::super::Bind;
use super::super::Endpoint;
use super::super::PlatformBind;

use std::net::SocketAddr;

pub struct LinuxEndpoint {}

pub struct LinuxBind {}

impl Endpoint for LinuxEndpoint {
    fn clear_src(&mut self) {}

    fn from_address(addr: SocketAddr) -> Self {
        LinuxEndpoint {}
    }

    fn into_address(&self) -> SocketAddr {
        "127.0.0.1:6060".parse().unwrap()
    }
}

/*
impl Bind for PlatformBind {
    type Endpoint = PlatformEndpoint;
}
*/
