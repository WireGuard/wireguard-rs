use arraydeque::ArrayDeque;
use spin::Mutex;

use std::mem;
use std::sync::atomic::{AtomicUsize, Ordering};

const QUEUE_SIZE: usize = 1024;

pub trait Job: Sized {
    fn queue(&self) -> &Queue<Self>;

    fn is_ready(&self) -> bool;

    fn parallel_work(&self);

    fn sequential_work(self);
}


pub struct Queue<J: Job> {
    contenders: AtomicUsize,
    queue: Mutex<ArrayDeque<[J; QUEUE_SIZE]>>,
}

impl<J: Job> Queue<J> {
    pub fn new() -> Queue<J> {
        Queue {
            contenders: AtomicUsize::new(0),
            queue: Mutex::new(ArrayDeque::new()),
        }
    }

    pub fn push(&self, job: J) -> bool {
        self.queue.lock().push_back(job).is_ok()
    }

    pub fn consume(&self) {
        // check if we are the first contender
        let pos = self.contenders.fetch_add(1, Ordering::Acquire);
        if pos > 0 {
            assert!(pos < usize::max_value(), "contenders overflow");
        }

        // enter the critical section
        let mut contenders = 1; // myself
        while contenders > 0 {
            // handle every ready element
            loop {
                let mut queue = self.queue.lock();

                // check if front job is ready
                match queue.front() {
                    None => break,
                    Some(job) => {
                        if job.is_ready() {
                            ()
                        } else {
                            break;
                        }
                    }
                };

                // take the job out of the queue
                let job = queue.pop_front().unwrap();
                debug_assert!(job.is_ready());
                mem::drop(queue);

                // process element
                job.sequential_work();
            }

            // decrease contenders
            contenders = self.contenders.fetch_sub(contenders, Ordering::Acquire) - contenders;
        }
    }
}
