use std::net::SocketAddr;

use super::super::Endpoint;

#[derive(Clone, Copy)]
pub struct UnitEndpoint {}

impl Endpoint for UnitEndpoint {
    fn from_address(_: SocketAddr) -> UnitEndpoint {
        UnitEndpoint {}
    }

    fn into_address(&self) -> SocketAddr {
        "127.0.0.1:8080".parse().unwrap()
    }

    fn clear_src(&mut self) {}
}

impl UnitEndpoint {
    pub fn new() -> UnitEndpoint {
        UnitEndpoint {}
    }
}
