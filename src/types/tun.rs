use std::error;

pub trait Tun: Send + Sync + 'static {
    type Error: error::Error;

    /// Returns the MTU of the device
    ///
    /// This function needs to be efficient (called for every read).
    /// The goto implementation stragtegy is to .load an atomic variable,
    /// then use e.g. netlink to update the variable in a seperate thread.
    ///
    /// # Returns
    ///
    /// The MTU of the interface in bytes
    fn mtu(&self) -> usize;

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

    /// Writes an IP packet to the tunnel device
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
