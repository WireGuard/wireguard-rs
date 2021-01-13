use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const PACKETS_PER_SECOND: u64 = 20;
const PACKETS_BURSTABLE: u64 = 5;
const PACKET_COST: u64 = 1_000_000_000 / PACKETS_PER_SECOND;
const MAX_TOKENS: u64 = PACKET_COST * PACKETS_BURSTABLE;

const GC_INTERVAL: Duration = Duration::from_secs(1);

struct Entry {
    pub last_time: Instant,
    pub tokens: u64,
}

pub struct RateLimiter(Arc<RateLimiterInner>);

struct RateLimiterInner {
    gc_running: AtomicBool,
    gc_dropped: (Mutex<bool>, Condvar),
    table: spin::RwLock<HashMap<IpAddr, spin::Mutex<Entry>>>,
}

impl Drop for RateLimiter {
    fn drop(&mut self) {
        // wake up & terminate any lingering GC thread
        let &(ref lock, ref cvar) = &self.0.gc_dropped;
        let mut dropped = lock.lock().unwrap();
        *dropped = true;
        cvar.notify_all();
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        #[allow(clippy::mutex_atomic)]
        RateLimiter(Arc::new(RateLimiterInner {
            gc_dropped: (Mutex::new(false), Condvar::new()),
            gc_running: AtomicBool::from(false),
            table: spin::RwLock::new(HashMap::new()),
        }))
    }

    pub fn allow(&self, addr: &IpAddr) -> bool {
        // check if allowed
        let allowed = {
            // check for existing entry (only requires read lock)
            if let Some(entry) = self.0.table.read().get(addr) {
                // update existing entry
                let mut entry = entry.lock();

                // add tokens earned since last time
                entry.tokens = MAX_TOKENS
                    .min(entry.tokens + u64::from(entry.last_time.elapsed().subsec_nanos()));
                entry.last_time = Instant::now();

                // subtract cost of packet
                if entry.tokens > PACKET_COST {
                    entry.tokens -= PACKET_COST;
                    return true;
                } else {
                    return false;
                }
            }

            // add new entry (write lock)
            self.0.table.write().insert(
                *addr,
                spin::Mutex::new(Entry {
                    last_time: Instant::now(),
                    tokens: MAX_TOKENS - PACKET_COST,
                }),
            );
            true
        };

        // check that GC thread is scheduled
        if !self.0.gc_running.swap(true, Ordering::Relaxed) {
            let limiter = self.0.clone();
            thread::spawn(move || {
                let &(ref lock, ref cvar) = &limiter.gc_dropped;
                let mut dropped = lock.lock().unwrap();
                while !*dropped {
                    // garbage collect
                    {
                        let mut tw = limiter.table.write();
                        tw.retain(|_, ref mut entry| {
                            entry.lock().last_time.elapsed() <= GC_INTERVAL
                        });
                        if tw.len() == 0 {
                            limiter.gc_running.store(false, Ordering::Relaxed);
                            return;
                        }
                    }

                    // wait until stopped or new GC (~1 every sec)
                    let res = cvar.wait_timeout(dropped, GC_INTERVAL).unwrap();
                    dropped = res.0;
                }
            });
        }

        allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std;

    struct Result {
        allowed: bool,
        text: &'static str,
        wait: Duration,
    }

    #[test]
    fn test_ratelimiter() {
        let ratelimiter = RateLimiter::new();
        let mut expected = vec![];
        let ips = vec![
            "127.0.0.1".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
            "172.167.2.3".parse().unwrap(),
            "97.231.252.215".parse().unwrap(),
            "248.97.91.167".parse().unwrap(),
            "188.208.233.47".parse().unwrap(),
            "104.2.183.179".parse().unwrap(),
            "72.129.46.120".parse().unwrap(),
            "2001:0db8:0a0b:12f0:0000:0000:0000:0001".parse().unwrap(),
            "f5c2:818f:c052:655a:9860:b136:6894:25f0".parse().unwrap(),
            "b2d7:15ab:48a7:b07c:a541:f144:a9fe:54fc".parse().unwrap(),
            "a47b:786e:1671:a22b:d6f9:4ab0:abc7:c918".parse().unwrap(),
            "ea1e:d155:7f7a:98fb:2bf5:9483:80f6:5445".parse().unwrap(),
            "3f0e:54a2:f5b4:cd19:a21d:58e1:3746:84c4".parse().unwrap(),
        ];

        for _ in 0..PACKETS_BURSTABLE {
            expected.push(Result {
                allowed: true,
                wait: Duration::new(0, 0),
                text: "initial burst",
            });
        }

        expected.push(Result {
            allowed: false,
            wait: Duration::new(0, 0),
            text: "after burst",
        });

        expected.push(Result {
            allowed: true,
            wait: Duration::new(0, PACKET_COST as u32),
            text: "filling tokens for single packet",
        });

        expected.push(Result {
            allowed: false,
            wait: Duration::new(0, 0),
            text: "not having refilled enough",
        });

        expected.push(Result {
            allowed: true,
            wait: Duration::new(0, 2 * PACKET_COST as u32),
            text: "filling tokens for 2 * packet burst",
        });

        expected.push(Result {
            allowed: true,
            wait: Duration::new(0, 0),
            text: "second packet in 2 packet burst",
        });

        expected.push(Result {
            allowed: false,
            wait: Duration::new(0, 0),
            text: "packet following 2 packet burst",
        });

        for item in expected {
            std::thread::sleep(item.wait);
            for ip in ips.iter() {
                if ratelimiter.allow(&ip) != item.allowed {
                    panic!(
                        "test failed for {} on {}. expected: {}, got: {}",
                        ip, item.text, item.allowed, !item.allowed
                    )
                }
            }
        }
    }
}
