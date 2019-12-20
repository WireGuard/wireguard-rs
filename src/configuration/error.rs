use std::error::Error;
use std::fmt;

#[cfg(unix)]
use libc::*;

#[derive(Debug)]
pub enum ConfigError {
    FailedToBind,
    InvalidHexValue,
    InvalidPortNumber,
    InvalidFwmark,
    InvalidKey,
    InvalidSocketAddr,
    InvalidKeepaliveInterval,
    InvalidAllowedIp,
    InvalidOperation,
    LineTooLong,
    IOError,
    UnsupportedValue,
    UnsupportedProtocolVersion,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConfigError(errno = {})", self.errno())
    }
}

impl Error for ConfigError {
    fn description(&self) -> &str {
        ""
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[cfg(unix)]
impl ConfigError {
    pub fn errno(&self) -> i32 {
        // TODO: obtain the correct errorno values
        match self {
            // insufficient perms
            ConfigError::FailedToBind => EPERM,

            // parsing of value failed
            ConfigError::InvalidHexValue => EINVAL,
            ConfigError::InvalidPortNumber => EINVAL,
            ConfigError::InvalidFwmark => EINVAL,
            ConfigError::InvalidSocketAddr => EINVAL,
            ConfigError::InvalidKeepaliveInterval => EINVAL,
            ConfigError::InvalidAllowedIp => EINVAL,
            ConfigError::InvalidOperation => EINVAL,
            ConfigError::UnsupportedValue => EINVAL,

            // other protocol errors
            ConfigError::LineTooLong => EPROTO,
            ConfigError::InvalidKey => EPROTO,
            ConfigError::UnsupportedProtocolVersion => EPROTO,

            // IO
            ConfigError::IOError => EIO,
        }
    }
}
