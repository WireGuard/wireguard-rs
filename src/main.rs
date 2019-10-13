#![feature(test)]
#![allow(dead_code)]

extern crate jemallocator;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

// mod config;
mod platform;
mod wireguard;

use platform::TunBind;

fn main() {
    let (readers, writers, mtu) = platform::PlatformTun::create("test").unwrap();
}
