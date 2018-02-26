#![feature(test)]

#[macro_use] extern crate failure;
#[macro_use] extern crate structopt_derive;
#[macro_use] extern crate log;

extern crate daemonize;
extern crate env_logger;
extern crate nix;
extern crate structopt;
extern crate wireguard;

use daemonize::Daemonize;
use failure::Error;
use wireguard::interface::Interface;
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

    if !opt.foreground {
        daemonize().expect("failed to daemonize");
    }

    Interface::new(&opt.interface).start();
}

fn daemonize() -> Result<(), Error> {
    if !nix::unistd::getuid().is_root() {
        bail!("You are not the root user which can spawn the daemon.");
    }

    debug!("Starting daemon.");
    let daemonize = Daemonize::new()
        .stream_redirect("/var/log/wireguard.log");

    daemonize.start()?;
    Ok(())
}
