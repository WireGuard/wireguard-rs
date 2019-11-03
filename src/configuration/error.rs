pub enum ConfigError {
    NoSuchPeer,
    NotListening,
    FailedToBind,
    InvalidHexValue,
    InvalidPortNumber,
    InvalidFwmark,
    InvalidKey,
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
            ConfigError::UnsupportedValue => 7,
            ConfigError::InvalidKey => 8,
            ConfigError::UnsupportedProtocolVersion => 9,
        }
    }
}
