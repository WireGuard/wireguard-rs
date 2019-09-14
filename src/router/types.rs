use std::error::Error;
use std::fmt;
use std::marker::PhantomData;

pub trait Opaque: Send + Sync + 'static {}

impl<T> Opaque for T where T: Send + Sync + 'static {}

/// A send/recv callback takes 3 arguments:
///
/// * `0`, a reference to the opaque value assigned to the peer
/// * `1`, a bool indicating whether the message contained data (not just keepalive)
/// * `2`, a bool indicating whether the message was transmitted (i.e. did the peer have an associated endpoint?)
pub trait Callback<T>: Fn(&T, usize, bool, bool) -> () + Sync + Send + 'static {}

impl<T, F> Callback<T> for F where F: Fn(&T, usize, bool, bool) -> () + Sync + Send + 'static {}

/// A key callback takes 1 argument
///
/// * `0`, a reference to the opaque value assigned to the peer
pub trait KeyCallback<T>: Fn(&T) -> () + Sync + Send + 'static {}

impl<T, F> KeyCallback<T> for F where F: Fn(&T) -> () + Sync + Send + 'static {}

pub trait Callbacks: Send + Sync + 'static {
    type Opaque: Opaque;
    fn send(_opaque: &Self::Opaque, _size: usize, _data: bool, _sent: bool) {}
    fn recv(_opaque: &Self::Opaque, _size: usize, _data: bool, _sent: bool) {}
    fn need_key(_opaque: &Self::Opaque) {}
}

#[derive(Debug)]
pub enum RouterError {
    NoCryptKeyRoute,
    MalformedIPHeader,
    MalformedTransportMessage,
    UnknownReceiverId,
    NoEndpoint,
    SendError,
}

impl fmt::Display for RouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouterError::NoCryptKeyRoute => write!(f, "No cryptkey route configured for subnet"),
            RouterError::MalformedIPHeader => write!(f, "IP header is malformed"),
            RouterError::MalformedTransportMessage => write!(f, "IP header is malformed"),
            RouterError::UnknownReceiverId => {
                write!(f, "No decryption state associated with receiver id")
            }
            RouterError::NoEndpoint => write!(f, "No endpoint for peer"),
            RouterError::SendError => write!(f, "Failed to send packet on bind"),
        }
    }
}

impl Error for RouterError {
    fn description(&self) -> &str {
        "Generic Handshake Error"
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}
