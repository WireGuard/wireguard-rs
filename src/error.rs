//! Everything related to error handling
use std::error::Error;
use std::{fmt, io, net, convert};

use log;
use std::ffi;

/// Common Tunnel Result type
pub type WgResult<T> = Result<T, WgError>;

/// The global Error type for wiki
pub struct WgError {
    /// A further description for the error
    description: String,

    #[allow(dead_code)]
    /// The cause for this error
    cause: Option<Box<Error>>,
}

/// Representation of an error case
impl WgError {
    /// Creates a new `WgError`
    pub fn new(description: &str) -> Self {
        WgError {
            description: description.to_string(),
            cause: None,
        }
    }

    /// Returns the corresponding `io::ErrorKind` for this error
    pub fn kind(&self) -> io::ErrorKind {
        io::ErrorKind::Other
    }
}

impl fmt::Display for WgError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description)
    }
}

impl fmt::Debug for WgError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl convert::From<WgError> for io::Error {
    fn from(tunnel_error: WgError) -> Self {
        io::Error::new(io::ErrorKind::Other, tunnel_error.description)
    }
}

impl Error for WgError {
    fn description(&self) -> &str {
        &self.description
    }
}

macro_rules! from_error {
    ($($p:ty,)*) => (
        $(impl From<$p> for WgError {
            fn from(err: $p) -> Self {
                WgError {
                    description: err.description().to_owned(),
                    cause: Some(Box::new(err)),
                }
            }
        })*
    )
}

from_error! {
    io::Error,
    log::SetLoggerError,
    ffi::NulError,
    net::AddrParseError,
}

macro_rules! bail {
    ($($fmt:tt)*) => (
        #[cfg_attr(feature = "cargo-clippy", allow(useless_format))]
        return Err(::error::WgError::new(&format!($($fmt)*)))
    )
}
