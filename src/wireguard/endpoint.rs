use spin::{Mutex, MutexGuard};
use std::sync::Arc;

use super::super::platform::Endpoint;

#[derive(Clone)]
struct EndpointStore<E: Endpoint> {
    endpoint: Arc<Mutex<Option<E>>>,
}

impl<E: Endpoint> EndpointStore<E> {
    pub fn new() -> EndpointStore<E> {
        EndpointStore {
            endpoint: Arc::new(Mutex::new(None)),
        }
    }

    pub fn set(&self, endpoint: E) {
        *self.endpoint.lock() = Some(endpoint);
    }

    pub fn get(&self) -> MutexGuard<Option<E>> {
        self.endpoint.lock()
    }

    pub fn clear_src(&self) {
        (*self.endpoint.lock()).as_mut().map(|e| e.clear_src());
    }
}
