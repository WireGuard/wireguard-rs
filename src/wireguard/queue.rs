use crossbeam_channel::{bounded, Receiver, Sender};
use std::sync::Mutex;

pub struct ParallelQueue<T> {
    queue: Mutex<Option<Sender<T>>>,
}

impl<T> ParallelQueue<T> {
    /// Create a new ParallelQueue instance
    ///
    /// # Arguments
    ///
    /// - `queues`: number of readers
    /// - `capacity`: capacity of each internal queue
    pub fn new(queues: usize, capacity: usize) -> (Self, Vec<Receiver<T>>) {
        let mut receivers = Vec::with_capacity(queues);
        let (tx, rx) = bounded(capacity);
        for _ in 0..queues {
            receivers.push(rx.clone());
        }
        (
            ParallelQueue {
                queue: Mutex::new(Some(tx)),
            },
            receivers,
        )
    }

    pub fn send(&self, v: T) {
        if let Some(s) = self.queue.lock().unwrap().as_ref() {
            let _ = s.send(v);
        }
    }

    pub fn close(&self) {
        *self.queue.lock().unwrap() = None;
    }
}
