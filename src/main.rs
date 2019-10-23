#![feature(test)]
#![allow(dead_code)]

extern crate jemallocator;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod configuration;
mod platform;
mod wireguard;

use platform::tun;

use configuration::WireguardConfig;

fn main() {
    /*
    let (mut readers, writer, mtu) = platform::TunInstance::create("test").unwrap();
    let wg = wireguard::Wireguard::new(readers, writer, mtu);
    */
}

/*
fn test_wg_configuration() {
    let (mut readers, writer, mtu) = platform::dummy::

    let wg = wireguard::Wireguard::new(readers, writer, mtu);
}
*/
