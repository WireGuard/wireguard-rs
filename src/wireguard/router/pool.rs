use arraydeque::ArrayDeque;
use spin::{Mutex, MutexGuard};
use std::sync::mpsc::Receiver;
use std::sync::Arc;

const INORDER_QUEUE_SIZE: usize = 64;

pub struct InnerJob<P, B> {
    // peer (used by worker to schedule/handle inorder queue),
    // when the peer is None, the job is complete
    peer: Option<P>,
    pub body: B,
}

pub struct Job<P, B> {
    inner: Arc<Mutex<InnerJob<P, B>>>,
}

impl<P, B> Clone for Job<P, B> {
    fn clone(&self) -> Job<P, B> {
        Job {
            inner: self.inner.clone(),
        }
    }
}

impl<P, B> Job<P, B> {
    pub fn new(peer: P, body: B) -> Job<P, B> {
        Job {
            inner: Arc::new(Mutex::new(InnerJob {
                peer: Some(peer),
                body,
            })),
        }
    }
}

impl<P, B> Job<P, B> {
    /// Returns a mutex guard to the inner job if complete
    pub fn complete(&self) -> Option<MutexGuard<InnerJob<P, B>>> {
        self.inner
            .try_lock()
            .and_then(|m| if m.peer.is_none() { Some(m) } else { None })
    }
}

pub struct InorderQueue<P, B> {
    queue: Mutex<ArrayDeque<[Job<P, B>; INORDER_QUEUE_SIZE]>>,
}

impl<P, B> InorderQueue<P, B> {
    pub fn send(&self, job: Job<P, B>) -> bool {
        self.queue.lock().push_back(job).is_ok()
    }

    pub fn new() -> InorderQueue<P, B> {
        InorderQueue {
            queue: Mutex::new(ArrayDeque::new()),
        }
    }

    #[inline(always)]
    pub fn handle<F: Fn(&mut InnerJob<P, B>)>(&self, f: F) {
        // take the mutex
        let mut queue = self.queue.lock();

        // handle all complete messages
        while queue
            .pop_front()
            .and_then(|j| {
                // check if job is complete
                let ret = if let Some(mut guard) = j.complete() {
                    f(&mut *guard);
                    false
                } else {
                    true
                };

                // return job to cyclic buffer if not complete
                if ret {
                    let _res = queue.push_front(j);
                    debug_assert!(_res.is_ok());
                    None
                } else {
                    // add job back to pool
                    Some(())
                }
            })
            .is_some()
        {}
    }
}

/// Allows easy construction of a semi-parallel worker.
/// Applicable for both decryption and encryption workers.
#[inline(always)]
pub fn worker_template<
    P, // represents a peer (atomic reference counted pointer)
    B, // inner body type (message buffer, key material, ...)
    W: Fn(&P, &mut B),
    S: Fn(&P, &mut B),
    Q: Fn(&P) -> &InorderQueue<P, B>,
>(
    receiver: Receiver<Job<P, B>>, // receiever for new jobs
    work_parallel: W,              // perform parallel / out-of-order work on peer
    work_sequential: S,            // perform sequential work on peer
    queue: Q,                      // resolve a peer to an inorder queue
) {
    loop {
        // handle new job
        let peer = {
            // get next job
            let job = match receiver.recv() {
                Ok(job) => job,
                _ => return,
            };

            // lock the job
            let mut job = job.inner.lock();

            // take the peer from the job
            let peer = job.peer.take().unwrap();

            // process job
            work_parallel(&peer, &mut job.body);
            peer
        };

        // process inorder jobs for peer
        queue(&peer).handle(|j| work_sequential(&peer, &mut j.body));
    }
}
