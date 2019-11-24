use std::error::Error;

pub enum TunEvent {
    Up(usize), // interface is up (supply MTU)
    Down,      // interface is down
}

pub trait Status: Send + 'static {
    type Error: Error;

    /// Returns status updates for the interface
    /// When the status is unchanged the method blocks
    fn event(&mut self) -> Result<TunEvent, Self::Error>;
}

pub trait Writer: Send + Sync + 'static {
    type Error: Error;

    /// Receive a cryptkey routed IP packet
    ///
    /// # Arguments
    ///
    /// - src: Buffer containing the IP packet to be written
    ///
    /// # Returns
    ///
    /// Unit type or an error
    fn write(&self, src: &[u8]) -> Result<(), Self::Error>;
}

pub trait Reader: Send + 'static {
    type Error: Error;

    /// Reads an IP packet into dst[offset:] from the tunnel device
    ///
    /// The reason for providing space for a prefix
    /// is to efficiently accommodate platforms on which the packet is prefaced by a header.
    /// This space is later used to construct the transport message inplace.
    ///
    /// # Arguments
    ///
    /// - buf: Destination buffer (enough space for MTU bytes + header)
    /// - offset: Offset for the beginning of the IP packet
    ///
    /// # Returns
    ///
    /// The size of the IP packet (ignoring the header) or an std::error::Error instance:
    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Self::Error>;
}

pub trait Tun: Send + Sync + 'static {
    type Writer: Writer;
    type Reader: Reader;
    type Status: Status;
    type Error: Error;
}

/// On some platforms the application can create the TUN device itself.
pub trait PlatformTun: Tun {
    fn create(name: &str) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Status), Self::Error>;
}
