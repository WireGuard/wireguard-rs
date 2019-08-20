use super::device::DecryptionState;
use super::device::DeviceInner;
use super::peer::PeerInner;

use crossbeam_deque::{Injector, Steal, Stealer, Worker};
use spin;
use std::iter;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver};
use std::sync::{Arc, Weak};
use std::thread;

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

struct JobInner {
    msg: Vec<u8>,   // message buffer (nonce and receiver id set)
    key: [u8; 32],  // chacha20poly1305 key
    status: Status, // state of the job
    op: Operation,  // should be buffer be encrypted / decrypted?
}

type JobBuffer = Arc<spin::Mutex<JobInner>>;
type JobParallel = (Arc<thread::JoinHandle<()>>, JobBuffer);
type JobInbound = (Arc<DecryptionState>, JobBuffer);
type JobOutbound = (Weak<PeerInner>, JobBuffer);

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

fn worker_inbound(
    device: Arc<DeviceInner>,   // related device
    peer: Arc<PeerInner>,       // related peer
    recv: Receiver<JobInbound>, // in order queue
) {
    // reads from in order channel
    for job in recv.recv().iter() {
        loop {
            let (state, buf) = job;

            // check if job is complete
            match buf.try_lock() {
                None => (),
                Some(buf) => {
                    if buf.status != Status::Waiting {
                        // check replay protector

                        // check if confirms keypair

                        // write to tun device

                        // continue to next job (no parking)
                        break;
                    }
                }
            }

            // wait for job to complete
            thread::park();
        }
    }
}

fn worker_outbound(
    device: Arc<DeviceInner>,   // related device
    peer: Arc<PeerInner>,       // related peer
    recv: Receiver<JobInbound>, // in order queue
) {
    // reads from in order channel
    for job in recv.recv().iter() {
        loop {
            let (peer, buf) = job;

            // check if job is complete
            match buf.try_lock() {
                None => (),
                Some(buf) => {
                    if buf.status != Status::Waiting {
                        // send buffer to peer endpoint
                        break;
                    }
                }
            }

            // wait for job to complete
            thread::park();
        }
    }
}

fn worker_parallel(
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
