#![allow(dead_code)]

use timestamp::Timestamp;

use failure::Error;
use futures::{unsync::mpsc, Async, Future, Poll, Stream, Sink};
use tokio::timer::Interval;
use tokio_core::reactor::Handle;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const PACKETS_PER_SECOND : u64 = 20;
const PACKETS_BURSTABLE  : u64 = 5;
const PACKET_COST        : u64 = 1_000_000_000 / PACKETS_PER_SECOND;
const MAX_TOKENS         : u64 = PACKET_COST * PACKETS_BURSTABLE;

lazy_static! {
    pub static ref GC_INTERVAL: Duration = Duration::new(1, 0);
}

struct Entry {
    pub last_time : Timestamp,
    pub tokens    : u64,
}

struct RateLimiter {
    table : HashMap<IpAddr, Entry>,
    rx    : mpsc::Receiver<()>,
}

impl RateLimiter {
    pub fn new(handle: &Handle) -> Result<Self, Error> {
        let (tx, rx) = mpsc::channel(128);
        let i_handle = handle.clone();

        let gc = Interval::new(Instant::now(), *GC_INTERVAL)
            .map_err(|e| panic!("timer failed; err={:?}", e))
            .for_each(move |_| {
                i_handle.spawn(tx.clone().send(()).then(|_| Ok(())));
                Ok(())
            });
        handle.spawn(gc);

        Ok(Self {
            table: HashMap::new(),
            rx
        })
    }

    fn _new_for_test() -> Self {
        let (_tx, rx) = mpsc::channel(1);
        Self { table: HashMap::new(), rx }
    }

    pub fn allow(&mut self, addr: &IpAddr) -> bool {
        if let Some(entry) = self.table.get_mut(addr) {
            entry.tokens    = MAX_TOKENS.min(entry.tokens + entry.last_time.elapsed().subsec_nanos() as u64);
            entry.last_time = Timestamp::now();

            if entry.tokens > PACKET_COST {
                entry.tokens -= PACKET_COST;
                return true;
            } else {
                return false;
            }
        }

        self.table.insert(*addr, Entry {
            last_time: Timestamp::now(),
            tokens: MAX_TOKENS - PACKET_COST
        });
        true
    }

    fn handle_gc(&mut self) {
        self.table.retain(|_, ref mut entry| entry.last_time.elapsed() <= *GC_INTERVAL);
    }
}

impl Future for RateLimiter {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.rx.poll() {
            Ok(Async::Ready(Some(()))) => self.handle_gc(),
            _ => {},
        }
        Ok(Async::NotReady)
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
        let mut ratelimiter = RateLimiter::_new_for_test();
        let mut expected    = vec![];
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
            "3f0e:54a2:f5b4:cd19:a21d:58e1:3746:84c4".parse().unwrap(),];

        for _ in 0..PACKETS_BURSTABLE {
            expected.push(Result {
                allowed : true,
                wait    : Duration::new(0, 0),
                text    : "inital burst",
            });
        }

        expected.push(Result {
            allowed : false,
            wait    : Duration::new(0, 0),
            text    : "after burst",
        });

        expected.push(Result {
            allowed : true,
            wait    : Duration::new(0, PACKET_COST as u32),
            text    : "filling tokens for single packet",
        });

        expected.push(Result {
            allowed : false,
            wait    : Duration::new(0, 0),
            text    : "not having refilled enough",
        });

        expected.push(Result {
            allowed : true,
            wait    : Duration::new(0, 2 * PACKET_COST as u32),
            text    : "filling tokens for 2 * packet burst",
        });

        expected.push(Result {
            allowed : true,
            wait    : Duration::new(0, 0),
            text    : "second packet in 2 packet burst",
        });

        expected.push(Result {
            allowed : false,
            wait    : Duration::new(0, 0),
            text    : "packet following 2 packet burst",
        });

        for item in expected {
            std::thread::sleep(item.wait);
            for ip in ips.iter() {
                if ratelimiter.allow(&ip) != item.allowed {
                    panic!("test failed for {} on {}. expected: {}, got: {}", ip, item.text, item.allowed, !item.allowed)
                }
            }
        }
    }
}