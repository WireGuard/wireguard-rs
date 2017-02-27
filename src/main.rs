//! The main executable for `WireGuard`

#[macro_use]
extern crate clap;
extern crate libc;

#[macro_use]
extern crate log;
extern crate mowl;
extern crate wireguard;

use clap::App;
use log::LogLevel;
use wireguard::{WireGuard, WgResult, WgError};

use std::process::exit;

fn main() {
    if let Err(error) = run() {
        error!("Error: {}", error);
        exit(1);
    }
}

fn run() -> WgResult<()> {
    // Load the CLI parameters from the yaml file
    let yaml = load_yaml!("cli.yaml");
    let app = App::from_yaml(yaml).version(crate_version!());
    let matches = app.get_matches();

    // Set the verbosity level
    let log_level = match matches.occurrences_of("verbose") {
        0 => LogLevel::Error,
        1 => LogLevel::Warn,
        2 => LogLevel::Info,
        3 => LogLevel::Debug,
        _ => LogLevel::Trace,
    };

    // Init the logging
    match mowl::init_with_level(log_level) {
        Err(_) => warn!("Log level already set"),
        Ok(_) => warn!("Log level set to: {}", log_level),
    }

    // Get the CLI matches
    let interface_name = matches.value_of("interface_name")
        .ok_or_else(|| WgError::new("No 'interface_name' provided"))?;
    let _ = matches.is_present("foreground");

    // Create a `WireGuard` instance
    let wireguard = WireGuard::new(interface_name)?;

    // Run the instance
    wireguard.run()?;

    Ok(())
}
