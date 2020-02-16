use arraydeque::ArrayDeque;
use spin::Mutex;

use std::mem;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::constants::INORDER_QUEUE_SIZE;

pub trait SequentialJob {
    fn is_ready(&self) -> bool;

    fn sequential_work(self);
}

pub trait ParallelJob: Sized + SequentialJob {
    fn queue(&self) -> &Queue<Self>;

    fn parallel_work(&self);
}

pub struct Queue<J: SequentialJob> {
    contenders: AtomicUsize,
    queue: Mutex<ArrayDeque<[J; INORDER_QUEUE_SIZE]>>,

    #[cfg(debug)]
    _flag: Mutex<()>,
}

impl<J: SequentialJob> Queue<J> {
    pub fn new() -> Queue<J> {
        Queue {
            contenders: AtomicUsize::new(0),
            queue: Mutex::new(ArrayDeque::new()),

            #[cfg(debug)]
            _flag: Mutex::new(()),
        }
    }

    pub fn push(&self, job: J) -> bool {
        self.queue.lock().push_back(job).is_ok()
    }

    pub fn consume(&self) {
        // check if we are the first contender
        let pos = self.contenders.fetch_add(1, Ordering::SeqCst);
        if pos > 0 {
            assert!(usize::max_value() > pos, "contenders overflow");
            return;
        }

        // enter the critical section
        let mut contenders = 1; // myself
        while contenders > 0 {
            // check soundness in debug builds
            #[cfg(debug)]
            let _flag = self
                ._flag
                .try_lock()
                .expect("contenders should ensure mutual exclusion");

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

            #[cfg(debug)]
            mem::drop(_flag);

            // decrease contenders
            contenders = self.contenders.fetch_sub(contenders, Ordering::SeqCst) - contenders;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::thread;

    use rand::thread_rng;
    use rand::Rng;

    struct TestJob {}

    impl SequentialJob for TestJob {
        fn is_ready(&self) -> bool {
            true
        }

        fn sequential_work(self) {}
    }

    /* Fuzz the Queue */
    #[test]
    fn test_queue() {
        fn hammer(queue: &Arc<Queue<TestJob>>) {
            let mut rng = thread_rng();
            for _ in 0..1_000_000 {
                if rng.gen() {
                    queue.push(TestJob {});
                } else {
                    queue.consume();
                }
            }
        }

        let queue = Arc::new(Queue::new());

        // repeatedly apply operations randomly from concurrent threads
        let other = {
            let queue = queue.clone();
            thread::spawn(move || hammer(&queue))
        };
        hammer(&queue);

        // wait, consume and check empty
        other.join().unwrap();
        queue.consume();
        assert_eq!(queue.queue.lock().len(), 0);
    }
}
