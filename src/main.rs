#![feature(test)]
#![feature(weak_into_raw)]

#[cfg(feature = "profiler")]
extern crate cpuprofiler;

#[cfg(feature = "profiler")]
use cpuprofiler::PROFILER;

mod configuration;
mod platform;
mod wireguard;

use log;

use daemonize::Daemonize;

use std::env;
use std::process::exit;
use std::thread;

use configuration::Configuration;

use platform::tun::{PlatformTun, Status};
use platform::uapi::{BindUAPI, PlatformUAPI};
use platform::*;

use wireguard::WireGuard;

#[cfg(feature = "profiler")]
fn profiler_stop() {
    println!("Stopping profiler");
    PROFILER.lock().unwrap().stop().unwrap();
}

#[cfg(not(feature = "profiler"))]
fn profiler_stop() {}

#[cfg(feature = "profiler")]
fn profiler_start(name: &str) {
    use std::path::Path;

    // find first available path to save profiler output
    let mut n = 0;
    loop {
        let path = format!("./{}-{}.profile", name, n);
        if !Path::new(path.as_str()).exists() {
            println!("Starting profiler: {}", path);
            PROFILER.lock().unwrap().start(path).unwrap();
            break;
        };
        n += 1;
    }
}

fn main() {
    // parse command line arguments
    let mut name = None;
    let mut drop_privileges = true;
    let mut foreground = false;
    let mut args = env::args();

    args.next(); // skip path (argv[0])

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
    let (mut readers, writer, status) = plt::Tun::create(name.as_str()).unwrap_or_else(|e| {
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

    // start profiler (if enabled)
    #[cfg(feature = "profiler")]
    profiler_start(name.as_str());

    // create WireGuard device
    let wg: WireGuard<plt::Tun, plt::UDP> = WireGuard::new(writer);

    // add all Tun readers
    while let Some(reader) = readers.pop() {
        wg.add_tun_reader(reader);
    }

    // wrap in configuration interface
    let cfg = configuration::WireGuardConfig::new(wg.clone());

    // start Tun event thread
    {
        let cfg = cfg.clone();
        let mut status = status;
        thread::spawn(move || loop {
            match status.event() {
                Err(e) => {
                    log::info!("Tun device error {}", e);
                    profiler_stop();
                    exit(0);
                }
                Ok(tun::TunEvent::Up(mtu)) => {
                    log::info!("Tun up (mtu = {})", mtu);

                    // bring the wireguard device up
                    cfg.up(mtu);

                    // start listening on UDP
                    let _ = cfg
                        .start_listener()
                        .map_err(|e| log::info!("Failed to start UDP listener: {}", e));
                }
                Ok(tun::TunEvent::Down) => {
                    log::info!("Tun down");

                    // set wireguard device down
                    cfg.down();

                    // close UDP listener
                    let _ = cfg
                        .stop_listener()
                        .map_err(|e| log::info!("Failed to stop UDP listener {}", e));
                }
            }
        });
    }

    // start UAPI server
    thread::spawn(move || loop {
        // accept and handle UAPI config connections
        match uapi.connect() {
            Ok(mut stream) => {
                let cfg = cfg.clone();
                thread::spawn(move || {
                    configuration::uapi::handle(&mut stream, &cfg);
                });
            }
            Err(err) => {
                log::info!("UAPI connection error: {}", err);
                profiler_stop();
                exit(0);
            }
        }
    });

    // block until all tun readers closed
    wg.wait();
    profiler_stop();
}
