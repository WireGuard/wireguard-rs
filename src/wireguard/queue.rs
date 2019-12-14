use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::Mutex;

/// A simple parallel queue used to pass work to a worker pool.
///
/// Unlike e.g. the crossbeam multi-producer multi-consumer queue
/// the ParallelQueue offers fewer features and instead improves speed:
///
/// The crossbeam channel ensures that elements are consumed
/// even if not every Receiver is being read from.
/// This is not ensured by ParallelQueue.
pub struct ParallelQueue<T> {
    next: AtomicUsize,                         // next round-robin index
    queues: Vec<Mutex<Option<SyncSender<T>>>>, // work queues (1 per thread)
}

impl<T> ParallelQueue<T> {
    /// Create a new ParallelQueue instance
    ///
    /// # Arguments
    ///
    /// - `queues`: number of readers
    /// - `capacity`: capacity of each internal queue
    ///
    pub fn new(queues: usize, capacity: usize) -> (Self, Vec<Receiver<T>>) {
        let mut rxs = vec![];
        let mut txs = vec![];

        for _ in 0..queues {
            let (tx, rx) = sync_channel(capacity);
            txs.push(Mutex::new(Some(tx)));
            rxs.push(rx);
        }

        (
            ParallelQueue {
                next: AtomicUsize::new(0),
                queues: txs,
            },
            rxs,
        )
    }

    pub fn send(&self, v: T) {
        let len = self.queues.len();
        let idx = self.next.fetch_add(1, Ordering::SeqCst);
        match self.queues[idx % len].lock().unwrap().as_ref() {
            Some(que) => {
                // TODO: consider best way to propergate Result
                let _ = que.send(v);
            }
            _ => (),
        }
    }

    pub fn close(&self) {
        for i in 0..self.queues.len() {
            let queue = &self.queues[i];
            *queue.lock().unwrap() = None;
        }
    }
}
