#![feature(test)]
#![allow(dead_code)]

extern crate jemallocator;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod configuration;
mod platform;
mod wireguard;

use log;

use std::env;

use platform::tun::PlatformTun;
use platform::uapi::{BindUAPI, PlatformUAPI};
use platform::*;

fn main() {
    let mut name = String::new();
    let mut foreground = false;

    for arg in env::args() {
        if arg == "--foreground" || arg == "-f" {
            foreground = true;
        } else {
            name = arg;
        }
    }

    if name == "" {
        return;
    }

    let _ = env_logger::builder().is_test(true).try_init();

    // create UAPI socket
    let uapi = plt::UAPI::bind(name.as_str()).unwrap();

    // create TUN device
    let (readers, writer, mtu) = plt::Tun::create(name.as_str()).unwrap();

    // create WireGuard device
    let wg: wireguard::Wireguard<plt::Tun, plt::Bind> =
        wireguard::Wireguard::new(readers, writer, mtu);

    // wrap in configuration interface and start UAPI server
    let cfg = configuration::WireguardConfig::new(wg);
    loop {
        match uapi.connect() {
            Ok(mut stream) => configuration::uapi::handle(&mut stream, &cfg),
            Err(err) => {
                log::info!("UAPI error: {:}", err);
                break;
            }
        }
    }
}
