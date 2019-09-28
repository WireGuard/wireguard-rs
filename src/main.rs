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

#[test]
fn test_pure_wireguard() {}

fn main() {}
