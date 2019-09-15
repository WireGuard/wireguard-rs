use std::net::SocketAddr;

pub trait Endpoint: Send {
    fn from_address(addr: SocketAddr) -> Self;
    fn into_address(&self) -> SocketAddr;
}
