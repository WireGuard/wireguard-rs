#![feature(test)]
#![allow(dead_code)]

extern crate jemallocator;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod configuration;
mod platform;
mod wireguard;

use platform::tun::PlatformTun;
use platform::uapi::PlatformUAPI;
use platform::*;

use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn main() {
    let name = "wg0";

    let _ = env_logger::builder().is_test(true).try_init();

    // create UAPI socket
    let uapi = plt::UAPI::bind(name).unwrap();

    // create TUN device
    let (readers, writer, mtu) = plt::Tun::create(name).unwrap();

    // create WireGuard device
    let wg: wireguard::Wireguard<plt::Tun, plt::Bind> =
        wireguard::Wireguard::new(readers, writer, mtu);

    // wrap in configuration interface and start UAPI server
    let cfg = configuration::WireguardConfig::new(wg);
    loop {
        let mut stream = uapi.accept().unwrap();
        configuration::uapi::handle(&mut stream.0, &cfg);
    }

    thread::sleep(Duration::from_secs(600));
}
