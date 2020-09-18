use arraydeque::ArrayDeque;
use spin::Mutex;

use core::mem;
use core::sync::atomic::{AtomicUsize, Ordering};

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
                        if !job.is_ready() {
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

    use std::thread;

    use std::sync::Arc;
    use std::time::Duration;

    use rand::thread_rng;
    use rand::Rng;

    #[test]
    fn test_consume_queue() {
        struct TestJob {
            cnt: Arc<AtomicUsize>,
            wait_sequential: Duration,
        }

        impl SequentialJob for TestJob {
            fn is_ready(&self) -> bool {
                true
            }

            fn sequential_work(self) {
                thread::sleep(self.wait_sequential);
                self.cnt.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn hammer(queue: &Arc<Queue<TestJob>>, cnt: Arc<AtomicUsize>) -> usize {
            let mut jobs = 0;
            let mut rng = thread_rng();
            for _ in 0..10_000 {
                if rng.gen() {
                    let wait_sequential: u64 = rng.gen();
                    let wait_sequential = wait_sequential % 1000;

                    let wait_parallel: u64 = rng.gen();
                    let wait_parallel = wait_parallel % 1000;

                    thread::sleep(Duration::from_micros(wait_parallel));

                    queue.push(TestJob {
                        cnt: cnt.clone(),
                        wait_sequential: Duration::from_micros(wait_sequential),
                    });
                    jobs += 1;
                } else {
                    queue.consume();
                }
            }
            queue.consume();
            jobs
        }

        let queue = Arc::new(Queue::new());
        let counter = Arc::new(AtomicUsize::new(0));

        // repeatedly apply operations randomly from concurrent threads
        let other = {
            let queue = queue.clone();
            let counter = counter.clone();
            thread::spawn(move || hammer(&queue, counter))
        };
        let mut jobs = hammer(&queue, counter.clone());

        // wait, consume and check empty
        jobs += other.join().unwrap();
        assert_eq!(queue.queue.lock().len(), 0, "elements left in queue");
        assert_eq!(
            jobs,
            counter.load(Ordering::Acquire),
            "did not consume every job"
        );
    }

    /* Fuzz the Queue */
    #[test]
    fn test_fuzz_queue() {
        struct TestJob {}

        impl SequentialJob for TestJob {
            fn is_ready(&self) -> bool {
                true
            }

            fn sequential_work(self) {}
        }

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
