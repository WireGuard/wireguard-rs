use std::thread;
use spin;
use lifeguard::Recycled;
use super::anti_replay::AntiReplay;
use std::sync::mpsc::{Receiver, sync_channel};
use std::sync::Arc;

struct ParallelJobInner {
    done : bool,
    msg  : Vec<u8>,
    key  : [u8; 32]
}

type ParallelJob = spin::Mutex<ParallelJobInner>;

struct InboundInorder {
    job : Arc<ParallelJob>,
    state : Arc<KeyState>,
}

struct Inorder<'a> (Arc<spin::Mutex<Option<Job<'a>>>>);

struct Job<'a> {
    msg : Recycled<'a, Vec<u8>>,
    arp : Arc<KeyState>,                    // replay protector and key-pair
    key : Option<(Arc<Peer>, Arc<KeyPair>)> // provided if the key has not been confirmed
}

fn worker_inorder<'a>(channel : Receiver<Inorder<'a>>) {
    let mut current = 0;

    // reads from inorder channel
    for ordered in channel.recv().iter() {
        
        loop {
            // check if job is complete
            match ordered.0.try_lock() {
                None => (),
                Some(guard) => if let Some(job) = *guard {
                    if job.arp.lock().update(6) {
                        // write to output

                        break;
                    }
                }
            }

            // wait for job to complete
            thread::park();
        }
    }
}