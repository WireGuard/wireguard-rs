use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use hjul::{Runner, Timer};

use crate::constants::*;
use crate::router::Callbacks;
use crate::types::{Bind, Tun};
use crate::wireguard::Peer;

pub struct Timers {
    handshake_pending: AtomicBool,
    handshake_attempts: AtomicUsize,

    retransmit_handshake: Timer,
    send_keepalive: Timer,
    zero_key_material: Timer,
    new_handshake: Timer,
}

impl Timers {
    pub fn new<T, B>(runner: &Runner, peer: Peer<T, B>) -> Timers
    where
        T: Tun,
        B: Bind,
    {
        // create a timer instance for the provided peer
        Timers {
            handshake_pending: AtomicBool::new(false),
            handshake_attempts: AtomicUsize::new(0),
            retransmit_handshake: {
                let peer = peer.clone();
                runner.timer(move || {
                    if peer.timers.read().handshake_retry() {
                        peer.new_handshake();
                    }
                })
            },
            new_handshake: {
                let peer = peer.clone();
                runner.timer(move || {
                    peer.new_handshake();
                    peer.timers.read().handshake_begun();
                })
            },
            send_keepalive: {
                let peer = peer.clone();
                runner.timer(move || {
                    peer.router.keepalive();
                    let keepalive = peer.keepalive.load(Ordering::Acquire);
                    if keepalive > 0 {
                        peer.timers
                            .read()
                            .send_keepalive
                            .reset(Duration::from_secs(keepalive as u64))
                    }
                })
            },
            zero_key_material: {
                let peer = peer.clone();
                runner.timer(move || {
                    peer.router.zero_keys();
                })
            },
        }
    }

    fn handshake_begun(&self) {
        self.handshake_pending.store(true, Ordering::SeqCst);
        self.handshake_attempts.store(0, Ordering::SeqCst);
        self.retransmit_handshake.reset(REKEY_TIMEOUT);
    }

    fn handshake_retry(&self) -> bool {
        if self.handshake_attempts.fetch_add(1, Ordering::SeqCst) <= MAX_TIMER_HANDSHAKES {
            self.retransmit_handshake.reset(REKEY_TIMEOUT);
            true
        } else {
            self.handshake_pending.store(false, Ordering::SeqCst);
            false
        }
    }

    pub fn dummy(runner: &Runner) -> Timers {
        Timers {
            handshake_pending: AtomicBool::new(false),
            handshake_attempts: AtomicUsize::new(0),
            retransmit_handshake: runner.timer(|| {}),
            new_handshake: runner.timer(|| {}),
            send_keepalive: runner.timer(|| {}),
            zero_key_material: runner.timer(|| {}),
        }
    }

    pub fn handshake_sent(&self) {
        self.send_keepalive.stop();
    }
}

/* Instance of the router callbacks */

pub struct Events<T, B>(PhantomData<(T, B)>);

impl<T: Tun, B: Bind> Callbacks for Events<T, B> {
    type Opaque = Peer<T, B>;

    fn send(peer: &Peer<T, B>, size: usize, data: bool, sent: bool) {
        peer.tx_bytes.fetch_add(size as u64, Ordering::Relaxed);
    }

    fn recv(peer: &Peer<T, B>, size: usize, data: bool, sent: bool) {
        peer.rx_bytes.fetch_add(size as u64, Ordering::Relaxed);
    }

    fn need_key(peer: &Peer<T, B>) {
        let timers = peer.timers.read();
        if !timers.handshake_pending.swap(true, Ordering::SeqCst) {
            timers.handshake_attempts.store(0, Ordering::SeqCst);
            timers.new_handshake.fire();
        }
    }
}
