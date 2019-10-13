use super::Endpoint;
use std::error::Error;

pub trait Reader<E: Endpoint>: Send + Sync {
    type Error: Error;

    fn read(&self, buf: &mut [u8]) -> Result<(usize, E), Self::Error>;
}

pub trait Writer<E: Endpoint>: Send + Sync + Clone + 'static {
    type Error: Error;

    fn write(&self, buf: &[u8], dst: &E) -> Result<(), Self::Error>;
}

pub trait Bind: Send + Sync + 'static {
    type Error: Error;
    type Endpoint: Endpoint;

    /* Until Rust gets type equality constraints these have to be generic */
    type Writer: Writer<Self::Endpoint>;
    type Reader: Reader<Self::Endpoint>;
}
