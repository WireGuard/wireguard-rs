#![feature(test)]
#![allow(dead_code)]

use log;

use daemonize::Daemonize;
use std::env;
use std::process::exit;
use std::thread;

mod configuration;
mod platform;
mod wireguard;

use platform::tun::PlatformTun;
use platform::uapi::{BindUAPI, PlatformUAPI};
use platform::*;

fn main() {
    // parse commandline arguments
    let mut name = None;
    let mut drop_privileges = true;
    let mut foreground = false;
    let mut args = env::args();

    args.next(); // skip path

    for arg in args {
        match arg.as_str() {
            "--foreground" | "-f" => {
                foreground = true;
            }
            "--root" => {
                drop_privileges = false;
            }
            dev => name = Some(dev.to_owned()),
        }
    }

    // unwrap device name
    let name = match name {
        None => {
            eprintln!("No device name supplied");
            exit(-1);
        }
        Some(name) => name,
    };

    // create UAPI socket
    let uapi = plt::UAPI::bind(name.as_str()).unwrap_or_else(|e| {
        eprintln!("Failed to create UAPI listener: {}", e);
        exit(-2);
    });

    // create TUN device
    let (readers, writer, status) = plt::Tun::create(name.as_str()).unwrap_or_else(|e| {
        eprintln!("Failed to create TUN device: {}", e);
        exit(-3);
    });

    // daemonize
    if !foreground {
        let daemonize = Daemonize::new()
            .pid_file(format!("/tmp/wgrs-{}.pid", name))
            .chown_pid_file(true)
            .working_directory("/tmp")
            .user("nobody")
            .group("daemon")
            .umask(0o777);
        daemonize.start().expect("Failed to daemonize");
    }

    // start logging
    env_logger::builder()
        .try_init()
        .expect("Failed to initialize event logger");

    // drop privileges
    if drop_privileges {}

    // create WireGuard device
    let wg: wireguard::Wireguard<plt::Tun, plt::UDP> = wireguard::Wireguard::new(readers, writer);

    wg.set_mtu(1420);

    // start Tun event thread
    /*
    {
        let wg = wg.clone();
        let mut status = status;
        thread::spawn(move || loop {
            match status.event() {
                Err(_) => break,
                Ok(tun::TunEvent::Up(mtu)) => {
                    wg.mtu.store(mtu, Ordering::Relaxed);
                }
                Ok(tun::TunEvent::Down) => {}
            }
        });
    }
    */

    // handle TUN updates up/down

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
