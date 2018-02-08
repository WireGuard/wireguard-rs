#![feature(ip_constructors)]
#![feature(option_filter)]
#![feature(try_trait)]
#![feature(test)]
#![allow(unused_imports)]

#[macro_use] extern crate failure;
#[macro_use] extern crate futures;
#[macro_use] extern crate log;
#[macro_use] extern crate structopt_derive;

extern crate base64;
extern crate blake2_rfc;
extern crate byteorder;
extern crate bytes;
extern crate daemonize;
extern crate env_logger;
extern crate hex;
extern crate nix;
extern crate pnet;
extern crate rand;
extern crate snow;
extern crate socket2;
extern crate structopt;
extern crate test;
extern crate time;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_uds;
extern crate tokio_utun;
extern crate tokio_timer;
extern crate treebitmap;

mod consts;
mod error;
mod interface;
mod protocol;
mod types;
mod anti_replay;
mod router;

use std::path::PathBuf;

use daemonize::Daemonize;
use interface::Interface;
use structopt::StructOpt;

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
    #[structopt(help = "WireGuard interface name", default_value = "utun4")]
    interface: String,

    /// An optional parameter, will be `None` if not present on the
    /// command line.
    #[structopt(help = "Output file, stdout if not present")]
    output: Option<String>,
}

fn main() {
    env_logger::init().unwrap();
    let opt = Opt::from_args();

//    if !opt.foreground {
//        daemonize().expect("failed to daemonize");
//    }

    Interface::new(&opt.interface).start();
}

//fn daemonize() -> Result<()> {
//    if !nix::unistd::getuid().is_root() {
//        bail!("You are not the root user which can spawn the daemon.");
//    }
//
//    debug!("Starting daemon.");
//
//    let pid_path = PathBuf::new(); // TODO temporary
//
////    let pid_path = WireGuard::get_run_path();
//
//    let daemonize = Daemonize::new()
//        .pid_file(pid_path.join("wireguard.pid"))
//        .chown_pid_file(true)
//        .working_directory(pid_path)
//        .user("nobody")
//        .group("daemon")
//        .umask(0o077);
//
//    daemonize.start()?;
//    Ok(())
//}
