use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use lazy_static::lazy_static;

const PACKETS_PER_SECOND: u64 = 20;
const PACKETS_BURSTABLE: u64 = 5;
const PACKET_COST: u64 = 1_000_000_000 / PACKETS_PER_SECOND;
const MAX_TOKENS: u64 = PACKET_COST * PACKETS_BURSTABLE;

lazy_static! {
    pub static ref GC_INTERVAL: Duration = Duration::new(1, 0);
}

struct Entry {
    pub last_time: Instant,
    pub tokens: u64,
}

pub struct RateLimiter {
    garbage_collect: Instant,
    table: HashMap<IpAddr, Entry>,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            garbage_collect: Instant::now(),
            table: HashMap::new(),
        }
    }

    pub fn allow(&mut self, addr: &IpAddr) -> bool {
        // check for garbage collection
        if self.garbage_collect.elapsed() > *GC_INTERVAL {
            self.handle_gc();
        }

        // update existing entry
        if let Some(entry) = self.table.get_mut(addr) {
            // add tokens earned since last time
            entry.tokens =
                MAX_TOKENS.min(entry.tokens + u64::from(entry.last_time.elapsed().subsec_nanos()));
            entry.last_time = Instant::now();

            // subtract cost of packet
            if entry.tokens > PACKET_COST {
                entry.tokens -= PACKET_COST;
                return true;
            } else {
                return false;
            }
        }

        // add new entry
        self.table.insert(
            *addr,
            Entry {
                last_time: Instant::now(),
                tokens: MAX_TOKENS - PACKET_COST,
            },
        );

        true
    }

    fn handle_gc(&mut self) {
        self.table
            .retain(|_, ref mut entry| entry.last_time.elapsed() <= *GC_INTERVAL);
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
        let mut ratelimiter = RateLimiter::new();
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
                text: "inital burst",
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
