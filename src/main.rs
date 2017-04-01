//! The main executable for `WireGuard`

#[macro_use]
extern crate clap;
extern crate daemonize;
extern crate libc;
#[macro_use]
extern crate log;
extern crate mowl;
extern crate nix;
#[macro_use]
extern crate error_chain;

extern crate wireguard;

use clap::App;
use daemonize::Daemonize;
use log::LogLevel;
use wireguard::WireGuard;
use wireguard::error::*;

use std::process::exit;

fn main() {
    if let Err(error) = run() {
        error!("{}", error);
        exit(1);
    }
}

fn run() -> Result<()> {
    // Load the CLI parameters from the yaml file
    let yaml = load_yaml!("cli.yaml");
    let app = App::from_yaml(yaml).version(crate_version!());
    let matches = app.get_matches();

    // Set the verbosity level
    let log_level = match matches.occurrences_of("verbose") {
        0 => LogLevel::Info, // Default value
        1 => LogLevel::Debug,
        _ => LogLevel::Trace,
    };

    // Init the logging
    match mowl::init_with_level(log_level) {
        Err(_) => warn!("Log level already set"),
        Ok(_) => info!("Log level set to: {}", log_level),
    }

    // Get the CLI matches
    let interface_name = matches.value_of("interface_name").ok_or_else(|| "No 'interface_name' provided")?;

    // Create a `WireGuard` instance
    let wireguard = WireGuard::new(interface_name)?;

    // Run the instance in foreground if needed
    if !matches.is_present("foreground") {
        // Check if we are the root user
        if nix::unistd::getuid() != 0 {
            bail!("You are not the root user which can spawn the daemon.");
        }

        debug!("Starting daemon.");

        // Daemonize the process
        let pid_path = WireGuard::get_run_path();
        let daemonize = Daemonize::new()
            .pid_file(pid_path.join("wireguard.pid"))
            .chown_pid_file(true)
            .working_directory(pid_path)
            .user("nobody")
            .group("daemon")
            .umask(0o077);

        daemonize.start()?;
    }

    // Run the instance
    wireguard.run()?;

    Ok(())
}
