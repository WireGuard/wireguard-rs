pub trait Opaque: Send + Sync + 'static {}

impl<T> Opaque for T where T: Send + Sync + 'static {}

/// A send/recv callback takes 3 arguments:
///
/// * `0`, a reference to the opaque value assigned to the peer
/// * `1`, a bool indicating whether the message contained data (not just keepalive)
/// * `2`, a bool indicating whether the message was transmitted (i.e. did the peer have an associated endpoint?)
pub trait Callback<T>: Fn(&T, bool, bool) -> () + Sync + Send + 'static {}

impl<T, F> Callback<T> for F where F: Fn(&T, bool, bool) -> () + Sync + Send + 'static {}

/// A key callback takes 1 argument
///
/// * `0`, a reference to the opaque value assigned to the peer
pub trait KeyCallback<T>: Fn(&T) -> () + Sync + Send + 'static {}

impl<T, F> KeyCallback<T> for F where F: Fn(&T) -> () + Sync + Send + 'static {}

pub trait TunCallback<T>: Fn(&T, bool, bool) -> () + Sync + Send + 'static {}

pub trait BindCallback<T>: Fn(&T, bool, bool) -> () + Sync + Send + 'static {}

pub trait Endpoint: Send + Sync {}
