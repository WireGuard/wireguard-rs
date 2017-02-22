extern crate log;
extern crate wireguard;

use log::LogLevel;
use wireguard::WireGuard;

#[test]
fn server() {
    WireGuard::dummy().unwrap().init_logging(LogLevel::Debug).unwrap();
}
