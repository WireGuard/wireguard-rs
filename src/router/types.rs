pub trait Opaque: Send + Sync + 'static {}

impl<T> Opaque for T where T: Send + Sync + 'static {}

pub trait Callback<T>: Fn(&T, bool) -> () + Sync + Send + 'static {}

impl<T, F> Callback<T> for F where F: Fn(&T, bool) -> () + Sync + Send + 'static {}
