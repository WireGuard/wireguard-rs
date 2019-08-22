#![feature(test)]

mod constants;
mod handshake;
mod router;
mod timers;
mod types;

use std::sync::Arc;

use sodiumoxide;
use types::KeyPair;

fn main() {
    // choose optimal crypto implementations for platform
    sodiumoxide::init().unwrap();

    let mut router = router::Device::new(8);
    {
        let peer = router.new_peer();
    }
    loop {}
}
