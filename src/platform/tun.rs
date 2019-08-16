use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

pub trait Tun: Send + Sync {
    type Error;

    fn new(mtu: Arc<AtomicUsize>) -> Self;
    fn read(&self, dst: &mut [u8]) -> Result<usize, Self::Error>;
    fn write(&self, src: &[u8]) -> Result<(), Self::Error>;
}
