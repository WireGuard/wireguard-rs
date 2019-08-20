use std::net::SocketAddr;

/* The generic implementation (not supporting "sticky-sockets"),
 * is to simply use SocketAddr directly as the endpoint.
 */
pub trait Endpoint: Into<SocketAddr> {}
