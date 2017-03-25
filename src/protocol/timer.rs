// Copyright 2017 Guanhao Yin <sopium@mysterious.site>

// This file is part of WireGuard.rs.

// WireGuard.rs is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// WireGuard.rs is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with WireGuard.rs.  If not, see <https://www.gnu.org/licenses/>.

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

type Action = Box<Fn() + Send + Sync>;

lazy_static! {
    /// Global timer controller.
    pub static ref CONTROLLER: TimerController = TimerController::new();
}

struct Timer {
    activated: AtomicBool,
    // Actually, this is not used outside the big whole wheel mutex.
    // But how to tell the compiler that???
    rounds: AtomicUsize,
    action: Action,
}

pub struct TimerHandle {
    pos: AtomicUsize,
    timer: ArcTimer,
}

// A single round will be ~ 16 seconds.
// WireGuard timers are mostly in this range.
const WHEEL_SLOTS: usize = 128;
const TICK_MS: usize = 128;

// This is hashed timing wheel.
pub struct TimerController(Mutex<Wheel>);

struct Wheel {
    // Usually a linked list is used in each slot.
    // Use hash table for now, for implementation simplicity.
    // It's slower but should still have same complexity.
    wheel: Vec<HashSet<ArcTimer>>,
    cur: usize,
}

impl TimerController {
    fn new() -> Self {
        let con = Mutex::new(Wheel {
            wheel: ::std::iter::repeat(HashSet::new()).take(WHEEL_SLOTS).collect(),
            cur: 0,
        });

        thread::Builder::new().name("timer".to_string()).spawn(|| {
            loop {
                let tick_start = Instant::now();

                let mut to_run = Vec::new();
                let mut wheel = CONTROLLER.0.lock().unwrap();
                let cur = wheel.cur;
                wheel.cur = (wheel.cur + 1) % WHEEL_SLOTS;
                {
                    let slot = &mut wheel.wheel[cur];

                    slot.retain(|t| {
                        Arc::strong_count(&t.0) > 1
                    });

                    for t in slot.iter() {
                        // `fetch_sub` always wraps, doesn't it?
                        let rounds = t.rounds.fetch_sub(1, Ordering::Relaxed);
                        if t.activated.load(Ordering::Relaxed) && rounds == 0 {
                            to_run.push(t.clone());
                            t.activated.store(false, Ordering::Relaxed);
                        }
                    }
                }
                drop(wheel);

                for t in to_run {
                    (t.action)();
                }

                let spent = tick_start.elapsed();
                #[allow(non_snake_case)]
                let TICK = Duration::from_millis(TICK_MS as u64);

                if spent >= TICK {
                    warn!("timer tick processing time exceeds TICK!");
                } else {
                    thread::sleep(TICK - spent);
                }
            }
        }).unwrap();

        TimerController(con)
    }

    pub fn register_delay(&self, delay: Duration, action: Action) -> TimerHandle {
        let (offset, rounds) = calc_offset_and_rounds(delay);

        let mut wheel = self.0.lock().unwrap();
        let pos = (wheel.cur + offset) % WHEEL_SLOTS;

        let timer = Arc::new(Timer {
            activated: AtomicBool::new(false),
            rounds: AtomicUsize::new(rounds),
            action: action,
        });

        wheel.wheel[pos].insert(ArcTimer(timer.clone()));

        TimerHandle {
            pos: AtomicUsize::new(pos),
            timer: ArcTimer(timer),
        }
    }
}

impl TimerHandle {
    /// Create a dummy handle, that does not point to an actual timer.
    ///
    /// Dummy handles MUST NOT be adjusted!
    pub fn dummy() -> Self {
        TimerHandle {
            pos: AtomicUsize::new(0),
            timer: ArcTimer(Arc::new(Timer {
                activated: AtomicBool::new(false),
                rounds: AtomicUsize::new(0),
                action: Box::new(|| {}),
            })),
        }
    }

    pub fn activate(&self) {
        self.timer.activated.store(true, Ordering::Relaxed);
    }

    pub fn de_activate(&self) {
        self.timer.activated.store(false, Ordering::Relaxed);
    }

    pub fn adjust_and_activate(&self, secs: u64) {
        let (offset, rounds) = calc_offset_and_rounds(Duration::from_secs(secs));

        let mut wheel = CONTROLLER.0.lock().unwrap();
        let old_pos = self.pos.load(Ordering::Relaxed);
        let new_pos = (wheel.cur + offset) % WHEEL_SLOTS;
        self.pos.store(new_pos, Ordering::Relaxed);
        self.timer.rounds.store(rounds, Ordering::Relaxed);

        let t = wheel.wheel[old_pos].take(&self.timer).unwrap();
        wheel.wheel[new_pos].insert(t);

        self.timer.activated.store(true, Ordering::Relaxed);
    }

    pub fn adjust_and_activate_if_not_activated(&self, secs: u64) {
        if !self.timer.activated.load(Ordering::Relaxed) {
            self.adjust_and_activate(secs);
        }
    }
}

fn calc_offset_and_rounds(delay: Duration) -> (usize, usize) {
    let delay_ms = delay.as_secs() * 1000 + delay.subsec_nanos() as u64 / 1000000;
    let ticks = ::std::cmp::max(delay_ms as usize / TICK_MS, 1);
    let offset = ticks % WHEEL_SLOTS;
    let rounds = ticks / WHEEL_SLOTS;
    (offset, rounds)
}

/// Hash and Eq by pointer address.
#[derive(Clone)]
struct ArcTimer(Arc<Timer>);

impl Deref for ArcTimer {
    type Target = Timer;

    fn deref(&self) -> &Timer {
        self.0.deref()
    }
}

impl Hash for ArcTimer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.0.deref() as *const Timer).hash(state);
    }
}

impl PartialEq for ArcTimer {
    fn eq(&self, other: &ArcTimer) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ArcTimer {
}
