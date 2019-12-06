use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::mpsc::{Receiver, SyncSender};

use spin::Mutex;

pub struct ParallelQueue<T> {
    next: AtomicUsize,                 // next round-robin index
    queues: Vec<Mutex<SyncSender<T>>>, // work queues (1 per thread)
}

impl<T> ParallelQueue<T> {
    pub fn new(queues: usize) -> (Vec<Receiver<T>>, Self) {
        let mut rxs = vec![];
        let mut txs = vec![];

        for _ in 0..queues {
            let (tx, rx) = sync_channel(128);
            txs.push(Mutex::new(tx));
            rxs.push(rx);
        }

        (
            rxs,
            ParallelQueue {
                next: AtomicUsize::new(0),
                queues: txs,
            },
        )
    }

    pub fn send(&self, v: T) {
        let len = self.queues.len();
        let idx = self.next.fetch_add(1, Ordering::SeqCst);
        let que = self.queues[idx % len].lock();
        que.send(v).unwrap();
    }

    pub fn close(&self) {
        for i in 0..self.queues.len() {
            let (tx, _) = sync_channel(0);
            let queue = &self.queues[i];
            *queue.lock() = tx;
        }
    }
}
