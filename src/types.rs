use std::fmt;
use std::error::Error;

// config error

#[derive(Debug)]
pub struct ConfigError(String);

impl ConfigError {
    pub fn new(s : &str) -> Self {
        ConfigError(s.to_string())
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConfigError({})", self.0)
    }
}

impl Error for ConfigError {
    fn description(&self) -> &str {
        &self.0
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

// handshake error

#[derive(Debug)]
pub enum HandshakeError {
    DecryptionFailure,
    UnknownPublicKey,
    UnknownReceiverId,
    InvalidMessageFormat,
    OldTimestamp,
    InvalidState
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::DecryptionFailure =>
                write!(f, "Failed to AEAD:OPEN"),
            HandshakeError::UnknownPublicKey =>
                write!(f, "Unknown public key"),
            HandshakeError::UnknownReceiverId =>
                write!(f, "Receiver id not allocated to any handshake"),
            HandshakeError::InvalidMessageFormat =>
                write!(f, "Invalid handshake message format"),
            HandshakeError::OldTimestamp =>
                write!(f, "Timestamp is less/equal to the newest"),
            HandshakeError::InvalidState =>
                write!(f, "Message does not apply to handshake state")
        }
    }
}

impl Error for HandshakeError {
    fn description(&self) -> &str {
        "Generic Handshake Error"
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

// types for resulting key-material

#[derive(Debug)]
pub struct Key {
    pub key : [u8; 32],
    pub id  : u32
}

#[cfg(test)]
impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.key[..] == other.key[..]
    }
}

#[derive(Debug)]
pub struct KeyPair {
    pub confirmed : bool, // has the key-pair been confirmed?
    pub send      : Key,  // key for outbound messages
    pub recv      : Key   // key for inbound messages
}

pub type Output = (
    Option<Vec<u8>>, // message to send
    Option<KeyPair>  // resulting key-pair of successful handshake
);

// preshared key

pub type Psk = [u8; 32];
