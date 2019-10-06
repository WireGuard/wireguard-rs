#![feature(test)]

extern crate jemallocator;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod constants;
mod handshake;
mod router;
mod timers;
mod types;
mod wireguard;

#[cfg(test)]
mod tests {
    use crate::types::{dummy, Bind};
    use crate::wireguard::Wireguard;

    use std::thread;
    use std::time::Duration;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_pure_wireguard() {
        init();
        let wg = Wireguard::new(dummy::TunTest::new(), dummy::VoidBind::new());
        thread::sleep(Duration::from_millis(500));
    }
}

fn main() {}
