#![feature(test)]
#![allow(dead_code)]

extern crate jemallocator;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

// mod config;
mod constants;
mod handshake;
mod router;
mod timers;
mod types;
mod wireguard;

#[cfg(test)]
mod tests {
    use crate::types::tun::Tun;
    use crate::types::{bind, dummy, tun};
    use crate::wireguard::Wireguard;

    use std::thread;
    use std::time::Duration;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_pure_wireguard() {
        init();
        let (reader, writer, mtu) = dummy::TunTest::create("name").unwrap();
        let wg: Wireguard<dummy::TunTest, dummy::PairBind> = Wireguard::new(reader, writer, mtu);
        thread::sleep(Duration::from_millis(500));
    }
}

fn main() {}
