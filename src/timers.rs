use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hjul::{Runner, Timer};

use crate::router::Callbacks;

const ZERO_DURATION: Duration = Duration::from_micros(0);

pub struct TimersInner {
    handshake_pending: AtomicBool,
    handshake_attempts: AtomicUsize,

    retransmit_handshake: Timer,
    send_keepalive: Timer,
    zero_key_material: Timer,
    new_handshake: Timer,

    // stats
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
}

impl TimersInner {
    pub fn new(runner: &Runner) -> Timers {
        Arc::new(TimersInner {
            handshake_pending: AtomicBool::new(false),
            handshake_attempts: AtomicUsize::new(0),
            retransmit_handshake: runner.timer(|| {}),
            new_handshake: runner.timer(|| {}),
            send_keepalive: runner.timer(|| {}),
            zero_key_material: runner.timer(|| {}),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
        })
    }

    pub fn handshake_sent(&self) {
        self.send_keepalive.stop();
    }
}

pub type Timers = Arc<TimersInner>;

pub struct Events();

impl Callbacks for Events {
    type Opaque = Timers;

    fn send(t: &Timers, size: usize, data: bool, sent: bool) {
        t.tx_bytes.fetch_add(size as u64, Ordering::Relaxed);
    }

    fn recv(t: &Timers, size: usize, data: bool, sent: bool) {
        t.rx_bytes.fetch_add(size as u64, Ordering::Relaxed);
    }

    fn need_key(t: &Timers) {
        if !t.handshake_pending.swap(true, Ordering::SeqCst) {
            t.handshake_attempts.store(0, Ordering::SeqCst);
            t.new_handshake.reset(ZERO_DURATION);
        }
    }
}
