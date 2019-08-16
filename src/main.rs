#![feature(test)]

mod handshake;
mod platform;
mod router;
mod types;

use std::sync::Arc;

use sodiumoxide;
use types::KeyPair;

fn main() {
    // choose optimal crypto implementations for platform
    sodiumoxide::init().unwrap();

    let mut rdev = router::Device::new(8);

    let pref = rdev.add();
}
