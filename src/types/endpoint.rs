use std::net::SocketAddr;

pub trait Endpoint: Into<SocketAddr> + From<SocketAddr> {}

impl<T> Endpoint for T where T: Into<SocketAddr> + From<SocketAddr> {}