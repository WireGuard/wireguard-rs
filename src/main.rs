#![feature(test)]

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

use daemonize::Daemonize;
use failure::Error;
use fern::colors::{Color, ColoredLevelConfig};
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
    let opt = Opt::from_args();

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
        .level_for("wireguard", log::LevelFilter::Trace)
        .chain(std::io::stdout())
        .apply().unwrap();

    if !opt.foreground {
        daemonize().expect("failed to daemonize");
    }

    match Interface::new(&opt.interface).start() {
        Err(e) => error!("failed to start interface: {}", e),
        _ => {}
    }
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
