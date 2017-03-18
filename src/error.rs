//! Everything related to error handling.

use std::{ffi, io, net};

use daemonize;
use log;
use nix;

error_chain! {
    foreign_links {
        Daemonize(daemonize::DaemonizeError) #[doc="A daemonization error."];
        Nul(ffi::NulError) #[doc="An FFI null error."];
        Io(io::Error) #[doc="An I/O error."];
        Log(log::SetLoggerError) #[doc="A log configuration error."];
        AddrParse(net::AddrParseError) #[doc="An address parsing error."];
        Nix(nix::Error) #[doc="A `nix` crate error."];
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, error.description())
    }
}
