extern crate log;
extern crate wireguard;

use log::LogLevel;
use wireguard::WireGuard;

#[test]
fn server() {
    WireGuard::new("127.0.0.1:8080").unwrap().init_logging(LogLevel::Debug).unwrap();
}
