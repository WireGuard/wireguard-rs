use std::error;

/* Often times an a file descriptor in an atomic might suffice.
 */
pub trait Bind<Endpoint>: Send + Sync {
    type Error : error::Error;

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
    fn get_port(&self) -> u16;
    
    fn recv(&self, dst: &mut [u8]) -> Endpoint;
    fn send(&self, src: &[u8], dst: &Endpoint);
}
