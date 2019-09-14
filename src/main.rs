#![feature(test)]

extern crate jemallocator;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod constants;
mod handshake;
mod router;
mod types;
mod wireguard;

fn main() {}
