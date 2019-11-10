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
    UnsupportedValue,
    UnsupportedProtocolVersion,
}

impl ConfigError {
    fn errno(&self) -> i32 {
        // TODO: obtain the correct error values
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
            ConfigError::UnsupportedValue => 7,
            ConfigError::InvalidKey => 8,
            ConfigError::UnsupportedProtocolVersion => 9,
        }
    }
}
