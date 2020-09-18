use super::KeyPair;

use alloc::sync::Arc;
use core::fmt;

// TODO: no_std alternatives
use std::error::Error;

pub trait Opaque: Send + Sync + 'static {}

impl<T> Opaque for T where T: Send + Sync + 'static {}

/// A send/recv callback takes 3 arguments:
///
/// * `0`, a reference to the opaque value assigned to the peer
/// * `1`, a bool indicating whether the message contained data (not just keepalive)
/// * `2`, a bool indicating whether the message was transmitted (i.e. did the peer have an associated endpoint?)
pub trait Callback<T>: Fn(&T, usize, bool) + Sync + Send + 'static {}

impl<T, F> Callback<T> for F where F: Fn(&T, usize, bool) + Sync + Send + 'static {}

/// A key callback takes 1 argument
///
/// * `0`, a reference to the opaque value assigned to the peer
pub trait KeyCallback<T>: Fn(&T) + Sync + Send + 'static {}

impl<T, F> KeyCallback<T> for F where F: Fn(&T) + Sync + Send + 'static {}

pub trait Callbacks: Send + Sync + 'static {
    type Opaque: Opaque;
    fn send(opaque: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>, counter: u64);
    fn recv(opaque: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>);
    fn need_key(opaque: &Self::Opaque);
    fn key_confirmed(opaque: &Self::Opaque);
}

#[derive(Debug)]
pub enum RouterError {
    NoCryptoKeyRoute,
    MalformedTransportMessage,
    UnknownReceiverId,
    NoEndpoint,
    SendError,
}

impl fmt::Display for RouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouterError::NoCryptoKeyRoute => write!(f, "No cryptokey route configured for subnet"),
            RouterError::MalformedTransportMessage => write!(f, "Transport header is malformed"),
            RouterError::UnknownReceiverId => {
                write!(f, "No decryption state associated with receiver id")
            }
            RouterError::NoEndpoint => write!(f, "No endpoint for peer"),
            RouterError::SendError => write!(f, "Failed to send packet on bind"),
        }
    }
}

impl Error for RouterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        "Generic Handshake Error"
    }
}
