mod handshake;
mod types;

use sodiumoxide;

use handshake::Device;
use types::KeyPair;

fn main() {
    // choose optimal crypto implementations for platform
    sodiumoxide::init().unwrap();
}
