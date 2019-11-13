use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum ConfigError {
    NoSuchPeer,
    NotListening,
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

impl ConfigError {
    pub fn errno(&self) -> i32 {
        // TODO: obtain the correct errorno values
        match self {
            ConfigError::NoSuchPeer => 1,
            ConfigError::NotListening => 2,
            ConfigError::FailedToBind => 3,
            ConfigError::InvalidHexValue => 4,
            ConfigError::InvalidPortNumber => 5,
            ConfigError::InvalidFwmark => 6,
            ConfigError::InvalidSocketAddr => 10,
            ConfigError::InvalidKeepaliveInterval => 11,
            ConfigError::InvalidAllowedIp => 12,
            ConfigError::InvalidOperation => 15,
            ConfigError::UnsupportedValue => 7,
            ConfigError::LineTooLong => 13,
            ConfigError::InvalidKey => 8,
            ConfigError::UnsupportedProtocolVersion => 9,
            ConfigError::IOError => 14,
        }
    }
}
