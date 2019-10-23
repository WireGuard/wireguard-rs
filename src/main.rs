#![feature(test)]
#![allow(dead_code)]

extern crate jemallocator;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod configuration;
mod platform;
mod wireguard;

use platform::PlatformTun;

fn main() {
    let (readers, writer, mtu) = platform::TunInstance::create("test").unwrap();
}
