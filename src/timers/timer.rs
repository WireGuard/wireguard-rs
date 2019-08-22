use ferris::*;
use spin;
use std::collections::HashMap;
use std::mem;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::{Duration, Instant};
use std::u64;

type TimerID = u64;
type TimerKey = (u64, usize);
type Callback = (Arc<AtomicBool>, Box<dyn Fn() -> () + Send + 'static>);

const ACCURACY: Duration = Duration::from_millis(100);
const OFFSET: Duration = Duration::from_millis(1000);

struct RunnerInner {
    keys: AtomicU64,
    wheel: spin::Mutex<CopyWheel<TimerKey>>,
    running: AtomicBool,
    callback: spin::Mutex<HashMap<TimerID, Callback>>,
}

pub struct Timer {
    pending: Arc<AtomicBool>,
    runner: Weak<RunnerInner>,
    id: u64,
    cnt: AtomicUsize,
}

struct Runner(Arc<RunnerInner>, Option<thread::JoinHandle<()>>);

impl Runner {
    fn new() -> Self {
        let inner = Arc::new(RunnerInner {
            running: AtomicBool::new(true),
            callback: spin::Mutex::new(HashMap::new()),
            keys: AtomicU64::new(0),
            wheel: spin::Mutex::new(CopyWheel::<TimerKey>::new(vec![
                Resolution::HundredMs,
                Resolution::Sec,
                Resolution::Min,
            ])),
        });

        // start runner thread
        let handle = {
            let inner = inner.clone();
            thread::spawn(move || {
                let mut next = Instant::now() + ACCURACY;
                while inner.running.load(Ordering::Acquire) {
                    // sleep
                    let now = Instant::now();
                    if next > now {
                        thread::sleep(next - now);
                    }
                    next = next + ACCURACY;

                    // extract expired events
                    let expired = inner.wheel.lock().expire();

                    // handle expired events
                    for key in &expired {
                        if let Some((pending, callback)) = inner.callback.lock().get(&key.0) {
                            if pending.swap(false, Ordering::SeqCst) {
                                callback();
                            }
                        } else {
                            unreachable!()
                        };
                    }
                }
            })
        };

        Runner(inner, Some(handle))
    }

    pub fn timer(&self, callback: Box<dyn Fn() -> () + Send + 'static>) -> Timer {
        let id = self.0.keys.fetch_add(1, Ordering::Relaxed);
        let pending = Arc::new(AtomicBool::new(false));

        assert!(id < u64::MAX, "wrapping of ids");

        self.0
            .callback
            .lock()
            .insert(id, (pending.clone(), callback));

        Timer {
            id,
            pending: pending,
            runner: Arc::downgrade(&self.0.clone()),
            cnt: AtomicUsize::new(0),
        }
    }
}

impl Timer {
    pub fn reset(&self, duration: Duration) {
        if let Some(runner) = self.runner.upgrade() {
            let mut wheel = runner.wheel.lock();
            let cnt = self.cnt.fetch_add(1, Ordering::SeqCst);
            self.pending.store(true, Ordering::SeqCst);
            wheel.stop((self.id, cnt));
            wheel.start((self.id, cnt + 1), duration - OFFSET);
        }
    }

    pub fn start(&self, duration: Duration) {
        if self.pending.load(Ordering::Acquire) {
            return;
        }

        if let Some(runner) = self.runner.upgrade() {
            let mut wheel = runner.wheel.lock();
            if !self.pending.swap(true, Ordering::SeqCst) {
                let cnt = self.cnt.fetch_add(1, Ordering::SeqCst);
                wheel.start((self.id, cnt + 1), duration - OFFSET);
            }
        }
    }

    pub fn stop(&self) {
        if self.pending.load(Ordering::Acquire) {
            if let Some(runner) = self.runner.upgrade() {
                let mut wheel = runner.wheel.lock();
                if self.pending.swap(false, Ordering::SeqCst) {
                    let cnt = self.cnt.load(Ordering::SeqCst);
                    wheel.stop((self.id, cnt));
                }
            }
        }
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        // stop the callback thread
        self.0.running.store(false, Ordering::SeqCst);
        if let Some(handle) = mem::replace(&mut self.1, None) {
            handle.join().unwrap();
        }
    }
}
