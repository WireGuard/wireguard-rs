/* Often times an a file descriptor in an atomic might suffice.
 */
pub trait Bind<Endpoint>: Send + Sync {
    type Error;

    fn new() -> Self;
    fn set_port(&self, port: u16) -> Result<(), Self::Error>;
    fn get_port(&self) -> u16;
    fn recv(&self, dst: &mut [u8]) -> Endpoint;
    fn send(&self, src: &[u8], dst: &Endpoint);
}
