/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

#![feature(test)]
#![allow(unknown_lints)]
#![warn(clippy)]

#[macro_use] extern crate failure;
#[macro_use] extern crate structopt_derive;
#[macro_use] extern crate log;

extern crate chrono;
extern crate colored;
extern crate daemonize;
extern crate fern;
extern crate nix;
extern crate structopt;
extern crate wireguard;

use colored::*;
use daemonize::Daemonize;
use failure::Error;
use fern::colors::{Color, ColoredLevelConfig};
use wireguard::interface::Interface;
use structopt::StructOpt;

use std::{env, process};

#[derive(StructOpt, Debug)]
#[structopt(name = "wgrs", about = "WireGuard - a network tunnel")]
struct Opt {
    /// A flag, true if used in the command line.
    #[structopt(short = "d", long = "debug", help = "Activate debug mode")]
    debug: bool,

    /// An argument of type float, with a default value.
    #[structopt(short = "f", long = "foreground", help = "Run in the foreground")]
    foreground: bool,

    /// Needed parameter, the first on the command line.
    #[structopt(help = "WireGuard interface name")]
    interface: String,

    /// An optional parameter, will be `None` if not present on the
    /// command line.
    #[structopt(help = "Output file, stdout if not present")]
    output: Option<String>,
}

fn warning() {
    let should_quit = match env::var("WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD") {
        Ok(ref val) if val == "1" => false,
        _                         => true
    };

    println!("\nWARNING WARNING WARNING WARNING WARNING WARNING WARNING");
    println!("W                                                     G");
    println!("W   This is alpha software. It will very likely not   G");
    println!("W   do what it is supposed to do, and things may go   G");
    println!("W   horribly wrong. You have been warned. Proceed     G");
    println!("W   at your own risk.                                 G");
    if cfg!(target_os = "linux") {
        println!("W                                                     G");
        println!("W   Furthermore, you are running this software on a   G");
        println!("W   Linux kernel, which is probably unnecessary and   G");
        println!("W   foolish. This is because the Linux kernel has     G");
        println!("W   built-in first class support for WireGuard, and   G");
        println!("W   this support is much more refined than this       G");
        println!("W   program. For more information on installing the   G");
        println!("W   kernel module, please visit:                      G");
        println!("W           https://www.wireguard.com/install         G");
    }
    if should_quit {
        println!("W                                                     G");
        println!("W   If you still want to use this program, against    G");
        println!("W   the sage advice here, please first export this    G");
        println!("W   environment variable:                             G");
        println!("W   WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1    G");
    }

    println!("W                                                     G");
    println!("WARNING WARNING WARNING WARNING WARNING WARNING WARNING\n");

    if should_quit {
        process::exit(1);
    }
}

fn main() {
    let opt = Opt::from_args();

    warning();

    let interface = opt.interface.clone();
    let colors = ColoredLevelConfig::new()
        .debug(Color::Magenta)
        .info(Color::BrightBlue)
        .warn(Color::BrightYellow)
        .error(Color::BrightRed);
    fern::Dispatch::new()
        .format(move |out, message, record| {
            let pad = record.level() == log::Level::Warn || record.level() == log::Level::Info;
            out.finish(format_args!(
                "{} {}  {}{}  {}",
                chrono::Local::now().format("%H:%M:%S%.3f"),
                interface,
                colors.color(record.level()),
                if pad { " " } else { "" },
                message,
            ))
        })
        .level(log::LevelFilter::Info)
        .level_for("wireguard", log::LevelFilter::Debug)
        .chain(std::io::stdout())
        .apply().unwrap();

    if !opt.foreground {
        if let Err(e) = daemonize() {
            println!("{}", format!("ERROR: {}", e.cause()).bold().red());
            process::exit(1);
        }
    }

    if let Err(e) = Interface::new(&opt.interface).start() {
        error!("failed to start interface: {}", e);
    }
}

fn daemonize() -> Result<(), Error> {
    if !nix::unistd::getuid().is_root() {
        bail!("This must be run as root to initialize the tunnel.");
    }

    debug!("Starting daemon.");
    let daemonize = Daemonize::new()
        .stream_redirect("/var/log/wireguard.log");

    daemonize.start()?;
    Ok(())
}
