use std::mem;
use std::sync::{Condvar, Mutex};
use std::hash::Hash;

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::collections::VecDeque;

pub trait ToKey {
    type Key: Hash + Eq;
    fn to_key(&self) -> Self::Key;
}

pub struct RunQueue<T : ToKey> {
    cvar: Condvar,
    inner: Mutex<Inner<T>>,
}

struct Inner<T : ToKey> {
    stop: bool,
    queue: VecDeque<T>,
    members: HashMap<T::Key, usize>,
}

impl<T : ToKey> RunQueue<T> {
    pub fn close(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.stop = true;
        self.cvar.notify_all();
    }

    pub fn new() -> RunQueue<T> {
        RunQueue {
            cvar: Condvar::new(),
            inner: Mutex::new(Inner {
                stop:false,
                queue: VecDeque::new(),
                members: HashMap::new(),
            }),
        }
    }

    pub fn insert(&self, v: T) {
        let key = v.to_key();
        let mut inner = self.inner.lock().unwrap();
        match inner.members.entry(key) {
            Entry::Occupied(mut elem) => {
                *elem.get_mut() += 1;
            }
            Entry::Vacant(spot) => {
                // add entry to back of queue
                spot.insert(0);
                inner.queue.push_back(v);

                // wake a thread
                self.cvar.notify_one();
            }
        }
    }

    pub fn run<F: Fn(&T) -> ()>(&self, f: F) {
        let mut inner = self.inner.lock().unwrap();
        loop {
            // fetch next element
            let elem = loop {
                // run-queue closed
                if inner.stop {
                    return;
                }

                // try to pop from queue
                match inner.queue.pop_front() {
                    Some(elem) => {
                        break elem;
                    }
                    None => (),
                };

                // wait for an element to be inserted
                inner = self.cvar.wait(inner).unwrap();
            };

            // fetch current request number
            let key = elem.to_key();
            let old_n = *inner.members.get(&key).unwrap();
            mem::drop(inner); // drop guard

            // handle element
            f(&elem);

            // retake lock and check if should be added back to queue
            inner = self.inner.lock().unwrap();
            match inner.members.entry(key) {
                Entry::Occupied(occ) => {
                    if *occ.get() == old_n {
                        // no new requests since last, remove entry.
                        occ.remove();
                    } else {
                        // new requests, reschedule.
                        inner.queue.push_back(elem);
                    }
                }
                Entry::Vacant(_) => {
                    unreachable!();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::sync::Arc;
    use std::time::Duration;

    /*
    #[test]
    fn test_wait() {
        let queue: Arc<RunQueue<usize>> = Arc::new(RunQueue::new());

        {
            let queue = queue.clone();
            thread::spawn(move || {
                queue.run(|e| {
                    println!("t0 {}", e);
                    thread::sleep(Duration::from_millis(100));
                })
            });
        }

        {
            let queue = queue.clone();
            thread::spawn(move || {
                queue.run(|e| {
                    println!("t1 {}", e);
                    thread::sleep(Duration::from_millis(100));
                })
            });
        }

    }
    */
}