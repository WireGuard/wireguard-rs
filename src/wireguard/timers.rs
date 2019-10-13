use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use log::info;

use hjul::{Runner, Timer};

use super::constants::*;
use super::router::Callbacks;
use super::types::{bind, tun};
use super::wireguard::{Peer, PeerInner};

pub struct Timers {
    handshake_pending: AtomicBool,
    handshake_attempts: AtomicUsize,

    retransmit_handshake: Timer,
    send_keepalive: Timer,
    send_persistent_keepalive: Timer,
    sent_lastminute_handshake: AtomicBool,
    zero_key_material: Timer,
    new_handshake: Timer,
    need_another_keepalive: AtomicBool,
}

impl Timers {
    #[inline(always)]
    fn need_another_keepalive(&self) -> bool {
        self.need_another_keepalive.swap(false, Ordering::SeqCst)
    }
}

impl <T: tun::Tun, B: bind::Bind>Peer<T, B> {
    /* should be called after an authenticated data packet is sent */
    pub fn timers_data_sent(&self) {
        self.timers().new_handshake.start(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
    }

    /* should be called after an authenticated data packet is received */
    pub fn timers_data_received(&self) {
        if !self.timers().send_keepalive.start(KEEPALIVE_TIMEOUT) {
            self.timers().need_another_keepalive.store(true, Ordering::SeqCst)
        }
    }

    /* Should be called after any type of authenticated packet is sent, whether:
     * - keepalive
     * - data
     * - handshake
     */
    pub fn timers_any_authenticated_packet_sent(&self) {
        self.timers().send_keepalive.stop()
    }

    /* Should be called after any type of authenticated packet is received, whether:
     * - keepalive
     * - data
     * - handshake
     */
    pub fn timers_any_authenticated_packet_received(&self) {
        self.timers().new_handshake.stop();
    }

    /* Should be called after a handshake initiation message is sent. */
    pub fn timers_handshake_initiated(&self) {
        self.timers().send_keepalive.stop();
        self.timers().retransmit_handshake.reset(REKEY_TIMEOUT);
    }

    /* Should be called after a handshake response message is received and processed
     * or when getting key confirmation via the first data message.
     */
    pub fn timers_handshake_complete(&self) {
        self.timers().handshake_attempts.store(0, Ordering::SeqCst);
        self.timers().sent_lastminute_handshake.store(false, Ordering::SeqCst);
        // TODO: Store time in peer for config
        // self.walltime_last_handshake
    }

    /* Should be called after an ephemeral key is created, which is before sending a
     * handshake response or after receiving a handshake response.
     */
    pub fn timers_session_derived(&self) {
        self.timers().zero_key_material.reset(REJECT_AFTER_TIME * 3);
    }

    /* Should be called before a packet with authentication, whether
     * keepalive, data, or handshake is sent, or after one is received.
     */
    pub fn timers_any_authenticated_packet_traversal(&self) {
        let keepalive = self.state.keepalive.load(Ordering::Acquire);
        if keepalive > 0 {
            self.timers().send_persistent_keepalive.reset(Duration::from_secs(keepalive as u64));
        }
    }
}

impl Timers {
    pub fn new<T, B>(runner: &Runner, peer: Peer<T, B>) -> Timers
    where
        T: tun::Tun,
        B: bind::Bind,
    {
        // create a timer instance for the provided peer
        Timers {
            handshake_pending: AtomicBool::new(false),
            need_another_keepalive: AtomicBool::new(false),
            sent_lastminute_handshake: AtomicBool::new(false),
            handshake_attempts: AtomicUsize::new(0),
            retransmit_handshake: {
                let peer = peer.clone();
                runner.timer(move || {
                    if peer.timers().handshake_retry() {
                        info!("Retransmit handshake for {}", peer);
                        peer.new_handshake();
                    } else {
                        info!("Failed to complete handshake for {}", peer);
                        peer.router.purge_staged_packets();
                        peer.timers().send_keepalive.stop();
                        peer.timers().zero_key_material.start(REJECT_AFTER_TIME * 3);
                    }
                })
            },
            send_keepalive: {
                let peer = peer.clone();
                runner.timer(move || {
                    peer.router.send_keepalive();
                    if peer.timers().need_another_keepalive() {
                        peer.timers().send_keepalive.start(KEEPALIVE_TIMEOUT);
                    }
                })
            },
            new_handshake: {
                let peer = peer.clone();
                runner.timer(move || {
                    info!(
                        "Retrying handshake with {}, because we stopped hearing back after {} seconds", 
                        peer, 
                        (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT).as_secs()
                    );
                    peer.new_handshake();
                    peer.timers.read().handshake_begun();
                })
            },
            zero_key_material: {
                let peer = peer.clone();
                runner.timer(move || {
                    peer.router.zero_keys();
                })
            },
            send_persistent_keepalive: {
                let peer = peer.clone();
                runner.timer(move || {
                    let keepalive = peer.state.keepalive.load(Ordering::Acquire);
                    if keepalive > 0 {
                        peer.router.send_keepalive();
                        peer.timers().send_keepalive.stop();
                        peer.timers().send_persistent_keepalive.start(Duration::from_secs(keepalive as u64));
                    }
                })
            }
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

    pub fn updated_persistent_keepalive(&self, keepalive: usize) {
        if keepalive > 0 {
            self.send_persistent_keepalive.reset(Duration::from_secs(keepalive as u64));
        }
    }

    pub fn dummy(runner: &Runner) -> Timers {
        Timers {
            handshake_pending: AtomicBool::new(false),
            need_another_keepalive: AtomicBool::new(false),
            sent_lastminute_handshake: AtomicBool::new(false),
            handshake_attempts: AtomicUsize::new(0),
            retransmit_handshake: runner.timer(|| {}),
            new_handshake: runner.timer(|| {}),
            send_keepalive: runner.timer(|| {}),
            send_persistent_keepalive: runner.timer(|| {}),
            zero_key_material: runner.timer(|| {})
        }
    }

    pub fn handshake_sent(&self) {
        self.send_keepalive.stop();
    }
}

/* Instance of the router callbacks */

pub struct Events<T, B>(PhantomData<(T, B)>);

impl<T: tun::Tun, B: bind::Bind> Callbacks for Events<T, B> {
    type Opaque = Arc<PeerInner<B>>;

    fn send(peer: &Self::Opaque, size: usize, data: bool, sent: bool) {
        peer.tx_bytes.fetch_add(size as u64, Ordering::Relaxed);
    }

    fn recv(peer: &Self::Opaque, size: usize, data: bool, sent: bool) {
        peer.rx_bytes.fetch_add(size as u64, Ordering::Relaxed);
    }

    fn need_key(peer: &Self::Opaque) {
        let timers = peer.timers();
        if !timers.handshake_pending.swap(true, Ordering::SeqCst) {
            timers.handshake_attempts.store(0, Ordering::SeqCst);
            timers.new_handshake.fire();
        }
    }

    fn key_confirmed(peer: &Self::Opaque) {
        peer.timers().retransmit_handshake.stop();
    }
}
