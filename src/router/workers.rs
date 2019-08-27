use super::device::DecryptionState;
use super::device::DeviceInner;
use super::peer::PeerInner;

use crossbeam_deque::{Injector, Steal, Stealer, Worker};
use spin;
use std::iter;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, TryRecvError};
use std::sync::{Arc, Weak};
use std::thread;

use super::types::{Opaque, Callback, KeyCallback};

#[derive(PartialEq)]
enum Operation {
    Encryption,
    Decryption,
}

#[derive(PartialEq)]
enum Status {
    Fault,   // unsealing failed
    Done,    // job valid and complete
    Waiting, // job awaiting completion
}

pub struct JobInner {
    msg: Vec<u8>,   // message buffer (nonce and receiver id set)
    key: [u8; 32],  // chacha20poly1305 key
    status: Status, // state of the job
    op: Operation,  // should be buffer be encrypted / decrypted?
}

pub type JobBuffer = Arc<spin::Mutex<JobInner>>;
pub type JobParallel = (Arc<thread::JoinHandle<()>>, JobBuffer);
pub type JobInbound<T, S, R, K> = (Weak<DecryptionState<T, S, R, K>>, JobBuffer);
pub type JobOutbound = JobBuffer;

/* Strategy for workers acquiring a new job:
 *
 * 1. Try the local job queue (owned by the thread)
 * 2. Try fetching a batch of jobs from the global injector
 * 3. Attempt to steal jobs from other threads.
 */
fn find_task<T>(local: &Worker<T>, global: &Injector<T>, stealers: &[Stealer<T>]) -> Option<T> {
    local.pop().or_else(|| {
        iter::repeat_with(|| {
            global
                .steal_batch_and_pop(local)
                .or_else(|| stealers.iter().map(|s| s.steal()).collect())
        })
        .find(|s| !s.is_retry())
        .and_then(|s| s.success())
    })
}

fn wait_buffer(stopped: AtomicBool, buf: &JobBuffer) {
    while !stopped.load(Ordering::Acquire) {
        match buf.try_lock() {
            None => (),
            Some(buf) => {
                if buf.status == Status::Waiting {
                    return;
                }
            }
        };
        thread::park();
    }
}

fn wait_recv<T>(stopped: &AtomicBool, recv: &Receiver<T>) -> Result<T, TryRecvError> {
    while !stopped.load(Ordering::Acquire) {
        match recv.try_recv() {
            Err(TryRecvError::Empty) => (),
            value => {
                return value;
            }
        };
        thread::park();
    }
    return Err(TryRecvError::Disconnected);
}

pub fn worker_inbound<T : Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>>(
    device: Arc<DeviceInner<T, S, R, K>>, // related device
    peer: Arc<PeerInner<T, S, R, K>>, // related peer
    recv: Receiver<JobInbound<T, S, R, K>>, // in order queue
) {
    loop {
        match wait_recv(&peer.stopped, &recv) {
            Ok((state, buf)) => {
                while !peer.stopped.load(Ordering::Acquire) {
                    match buf.try_lock() {
                        None => (),
                        Some(buf) => {
                            if buf.status != Status::Waiting {
                                // consume
                                break;
                            }
                        }
                    };
                    thread::park();
                }
            }
            Err(_) => {
                break;
            }
        }
    }
}

pub fn worker_outbound<T : Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>>(
    device: Arc<DeviceInner<T, S, R, K>>, // related device
    peer: Arc<PeerInner<T, S, R, K>>, // related peer
    recv: Receiver<JobOutbound>, // in order queue
) {
    loop {
        match wait_recv(&peer.stopped, &recv) {
            Ok(buf) => {
                while !peer.stopped.load(Ordering::Acquire) {
                    match buf.try_lock() {
                        None => (),
                        Some(buf) => {
                            if buf.status != Status::Waiting {
                                // consume
                                break;
                            }
                        }
                    };
                    thread::park();
                }
            }
            Err(_) => {
                break;
            }
        }
    }
}

pub fn worker_parallel(
    stopped: Arc<AtomicBool>,      // stop workers (device has been dropped)
    parked: Arc<AtomicBool>,       // thread has been parked?
    local: Worker<JobParallel>,    // local job queue (local to thread)
    global: Injector<JobParallel>, // global job injector
    stealers: Vec<Stealer<JobParallel>>, // stealers (from other threads)
) {
    while !stopped.load(Ordering::SeqCst) {
        match find_task(&local, &global, &stealers) {
            Some(job) => {
                let (handle, buf) = job;

                // take ownership of the job buffer and complete it
                {
                    let mut buf = buf.lock();
                    match buf.op {
                        Operation::Encryption => {
                            // TODO: encryption
                            buf.status = Status::Done;
                        }
                        Operation::Decryption => {
                            // TODO: decryption
                            buf.status = Status::Done;
                        }
                    }
                }

                // ensure consumer is unparked
                handle.thread().unpark();
            }
            None => {
                // no jobs, park the worker
                parked.store(true, Ordering::Release);
                thread::park();
            }
        }
    }
}
