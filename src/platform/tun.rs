use std::error::Error;

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

pub trait MTU: Send + Sync + Clone + 'static {
    /// Returns the MTU of the device
    ///
    /// This function needs to be efficient (called for every read).
    /// The goto implementation strategy is to .load an atomic variable,
    /// then use e.g. netlink to update the variable in a separate thread.
    ///
    /// # Returns
    ///
    /// The MTU of the interface in bytes
    fn mtu(&self) -> usize;
}

pub trait Tun: Send + Sync + 'static {
    type Writer: Writer;
    type Reader: Reader;
    type MTU: MTU;
    type Error: Error;
}

/// On some platforms the application can create the TUN device itself.
pub trait Platform: Tun {
    fn create(name: &str) -> Result<(Vec<Self::Reader>, Self::Writer, Self::MTU), Self::Error>;
}
