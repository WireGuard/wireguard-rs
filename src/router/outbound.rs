use spin;
use std::thread;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, sync_channel};

struct JobInner {
    done   : bool,     // is encryption complete?
    msg    : Vec<u8>,  // transport message (id, nonce already set)
    key    : [u8; 32], // encryption key
    handle : thread::JoinHandle
}

type Job = Arc<spin::Mutex<JobInner>>;

fn worker_parallel()

fn worker_inorder(channel : Receiver<Job>) {
    for ordered in channel.recv().iter() {
        loop {
            // check if job is complete
            match ordered.try_lock() {
                None => (),
                Some(guard) => if guard.done {
                    // write to UDP interface
                }
            }

            // wait for job to complete
            thread::park();
        }
    }
}