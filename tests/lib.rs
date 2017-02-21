extern crate wireguard;
extern crate tokio_core;

use tokio_core::reactor::Core;
use wireguard::Wireguard;

#[test]
fn server() {
    // Setup tokio
    let mut core = Core::new().unwrap();
    let handle = core.handle();

    // Run the core with the tunnel
    let tunnel = Wireguard::new(&handle).unwrap();
    core.run(tunnel).unwrap();
}
