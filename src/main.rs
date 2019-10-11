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
mod tests;

fn main() {}
