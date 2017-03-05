extern crate wireguard;

use wireguard::WireGuard;

#[test]
fn new_wireguard() {
    WireGuard::new("wg0");
}
