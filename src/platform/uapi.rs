use std::error::Error;
use std::io::{Read, Write};

pub trait BindUAPI {
    type Stream: Read + Write;
    type Error: Error;

    fn accept(&self) -> Result<Self::Stream, Self::Error>;
}

pub trait PlatformUAPI {
    type Error: Error;
    type Bind: BindUAPI;

    fn bind(name: &str) -> Result<Self::Bind, Self::Error>;
}
