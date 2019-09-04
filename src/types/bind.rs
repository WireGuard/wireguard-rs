use super::Endpoint;
use std::error;

/// Traits representing the "internet facing" end of the VPN.
///
/// In practice this is a UDP socket (but the router interface is agnostic).
/// Often these traits will be implemented on the same type.

/// Bind interface provided to the router code
pub trait RouterBind: Send + Sync {
    type Error: error::Error;
    type Endpoint: Endpoint;

    /// Receive a buffer on the bind
    ///
    /// # Arguments
    ///
    /// - `buf`, buffer for storing the packet. If the buffer is too short, the packet should just be truncated.
    ///
    /// # Note
    ///
    /// The size of the buffer is derieved from the MTU of the Tun device.
    fn recv(&self, buf: &mut [u8]) -> Result<(usize, Self::Endpoint), Self::Error>;

    /// Send a buffer to the endpoint
    ///
    /// # Arguments
    ///
    /// - `buf`, packet src buffer (in practice the body of a UDP datagram)
    /// - `dst`, destination endpoint (in practice, src: (ip, port) + dst: (ip, port) for sticky sockets)
    ///
    /// # Returns
    ///
    /// The unit type or an error if transmission failed
    fn send(&self, buf: &[u8], dst: &Self::Endpoint) -> Result<(), Self::Error>;
}

/// Bind interface provided for configuration (setting / getting the port)
pub trait ConfigBind {
    type Error: error::Error;

    /// Return a new (unbound) instance of a configuration bind
    fn new() -> Self;

    /// Updates the port of the bind
    ///
    /// # Arguments
    ///
    /// - `port`, the new port to bind to. 0 means any available port.
    ///
    /// # Returns
    ///
    /// The unit type or an error, if binding fails
    fn set_port(&self, port: u16) -> Result<(), Self::Error>;

    /// Returns the current port of the bind
    fn get_port(&self) -> Option<u16>;

    /// Set the mark (e.g. on Linus this is the fwmark) on the bind
    ///
    /// # Arguments
    ///
    /// - `mark`, the mark to set
    ///
    /// # Note
    ///
    /// The mark should be retained accross calls to `set_port`.
    ///
    /// # Returns
    ///
    /// The unit type or an error, if the operation fails due to permission errors
    fn set_mark(&self, mark: u16) -> Result<(), Self::Error>;
}
