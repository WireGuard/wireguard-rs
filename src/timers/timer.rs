use ferris::*;
use spin;
use std::collections::HashMap;
use std::mem;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::thread;
use std::time::{Duration, Instant};
use std::u64;

extern crate test;

type TimerID = u64;
type TimerKey = (u64, usize);
type Callback = (Weak<TimerInner>, Box<dyn Fn() -> () + Send + 'static>);

const ACCURACY: Duration = Duration::from_millis(100);
const OFFSET: Duration = Duration::from_millis(1000);

struct RunnerInner {
    keys: AtomicU64,
    wheel: spin::Mutex<CopyWheel<TimerKey>>,
    running: AtomicBool,
    callback: spin::Mutex<HashMap<TimerID, Callback>>,
}

struct TimerInner {
    id: u64,
    pending: AtomicBool,
    runner: Weak<RunnerInner>,
    cnt: AtomicUsize,
}

#[derive(Clone)]
pub struct Timer(Arc<TimerInner>);

pub struct Runner(Arc<RunnerInner>, Option<thread::JoinHandle<()>>);

impl Runner {
    pub fn new() -> Self {
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
                    // sleep for 1 tick
                    let now = Instant::now();
                    if next > now {
                        thread::sleep(next - now);
                    }
                    next = now + ACCURACY;

                    // extract expired events
                    let expired = inner.wheel.lock().expire();

                    // handle expired events
                    for key in &expired {
                        let callbacks = inner.callback.lock();
                        let (timer, callback) = callbacks.get(&key.0).unwrap();
                        if let Some(timer) = timer.upgrade() {
                            if timer.pending.swap(false, Ordering::SeqCst) {
                                callback();
                            }
                        }
                    }
                }
            })
        };

        Runner(inner, Some(handle))
    }

    pub fn timer(&self, callback: Box<dyn Fn() -> () + Send + 'static>) -> Timer {
        let id = self.0.keys.fetch_add(1, Ordering::Relaxed);
        let inner = Arc::new(TimerInner {
            id,
            pending: AtomicBool::new(false),
            runner: Arc::downgrade(&self.0.clone()),
            cnt: AtomicUsize::new(0),
        });

        assert!(id < u64::MAX, "wrapping of ids");

        self.0
            .callback
            .lock()
            .insert(id, (Arc::downgrade(&inner), callback));

        Timer(inner)
    }
}

impl Timer {
    pub fn reset(&self, duration: Duration) {
        let timer = &self.0;
        if let Some(runner) = timer.runner.upgrade() {
            let mut wheel = runner.wheel.lock();
            let cnt = timer.cnt.fetch_add(1, Ordering::SeqCst);
            timer.pending.store(true, Ordering::SeqCst);
            wheel.stop((timer.id, cnt));
            wheel.start((timer.id, cnt + 1), duration - OFFSET);
        }
    }

    pub fn start(&self, duration: Duration) {
        let timer = &self.0;
        if timer.pending.load(Ordering::Acquire) {
            return;
        }

        if let Some(runner) = timer.runner.upgrade() {
            let mut wheel = runner.wheel.lock();
            if !timer.pending.swap(true, Ordering::SeqCst) {
                let cnt = timer.cnt.fetch_add(1, Ordering::SeqCst);
                wheel.start((timer.id, cnt + 1), duration - OFFSET);
            }
        }
    }

    pub fn stop(&self) {
        let timer = &self.0;
        if timer.pending.load(Ordering::Acquire) {
            if let Some(runner) = timer.runner.upgrade() {
                let mut wheel = runner.wheel.lock();
                if timer.pending.swap(false, Ordering::SeqCst) {
                    let cnt = timer.cnt.load(Ordering::SeqCst);
                    wheel.stop((timer.id, cnt));
                }
            }
        }
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        self.0.running.store(false, Ordering::SeqCst);
        if let Some(handle) = mem::replace(&mut self.1, None) {
            handle.join().unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_reset(b: &mut Bencher) {
        let runner = Runner::new();
        let timer = runner.timer(Box::new(|| {}));
        b.iter(|| timer.reset(Duration::from_millis(1000)));
    }

    #[bench]
    fn bench_start(b: &mut Bencher) {
        let runner = Runner::new();
        let timer = runner.timer(Box::new(|| {}));
        b.iter(|| timer.start(Duration::from_millis(1000)));
    }
}
