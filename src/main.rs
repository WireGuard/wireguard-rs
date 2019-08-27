#![feature(test)]

mod constants;
mod handshake;
mod router;
mod types;

use hjul::*;

use std::sync::Arc;
use std::time::Duration;

use sodiumoxide;
use types::KeyPair;

#[derive(Debug, Clone)]
struct PeerTimer {
    a: Timer,
    b: Timer,
}

fn main() {
    let runner = Runner::new(Duration::from_millis(100), 1000, 1024);

    // choose optimal crypto implementations for platform
    sodiumoxide::init().unwrap();

    let router = router::Device::new(
        4,
        |t: &PeerTimer, data: bool, sent: bool| t.a.reset(Duration::from_millis(1000)),
        |t: &PeerTimer, data: bool, sent: bool| t.b.reset(Duration::from_millis(1000)),
        |t: &PeerTimer| println!("new key requested"),
    );

    let pt = PeerTimer {
        a: runner.timer(|| println!("timer-a fired for peer")),
        b: runner.timer(|| println!("timer-b fired for peer")),
    };

    let peer = router.new_peer(pt.clone());

    println!("{:?}", pt);
}
