use super::Endpoint;
use std::error;

/* Often times an a file descriptor in an atomic might suffice.
 */
pub trait Bind: Send + Sync + Clone + 'static {
    type Error: error::Error + Send;
    type Endpoint: Endpoint;

    fn new() -> Self;

    /// Updates the port of the Bind
    ///
    /// # Arguments
    ///
    /// - port, The new port to bind to. 0 means any available port.
    ///
    /// # Returns
    ///
    /// The unit type or an error, if binding fails
    fn set_port(&self, port: u16) -> Result<(), Self::Error>;

    /// Returns the current port of the bind
    fn get_port(&self) -> Option<u16>;

    fn recv(&self, buf: &mut [u8]) -> Result<(usize, Self::Endpoint), Self::Error>;

    fn send(&self, buf: &[u8], dst: &Self::Endpoint) -> Result<(), Self::Error>;
}
