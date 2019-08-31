use std::marker::PhantomData;

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

pub trait Endpoint: Send + Sync {}

pub trait Callbacks: Send + Sync + 'static {
    type Opaque: Opaque;
    type CallbackRecv: Callback<Self::Opaque>;
    type CallbackSend: Callback<Self::Opaque>;
    type CallbackKey: KeyCallback<Self::Opaque>;
}

/* Concrete implementation of "Callbacks",
 * used to hide the constituent type parameters.
 *
 * This type is never instantiated.
 */
pub struct PhantomCallbacks<O: Opaque, R: Callback<O>, S: Callback<O>, K: KeyCallback<O>> {
    _phantom_opaque: PhantomData<O>,
    _phantom_recv: PhantomData<R>,
    _phantom_send: PhantomData<S>,
    _phantom_key: PhantomData<K>,
}

impl<O: Opaque, R: Callback<O>, S: Callback<O>, K: KeyCallback<O>> Callbacks
    for PhantomCallbacks<O, R, S, K>
{
    type Opaque = O;
    type CallbackRecv = R;
    type CallbackSend = S;
    type CallbackKey = K;
}
