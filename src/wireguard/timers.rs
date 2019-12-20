use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use hjul::{Runner, Timer};
use log::debug;

use super::constants::*;
use super::peer::{Peer, PeerInner};
use super::router::{message_data_len, Callbacks};
use super::tun::Tun;
use super::types::KeyPair;
use super::udp::UDP;

pub struct Timers {
    // only updated during configuration
    enabled: bool,
    keepalive_interval: u64,

    handshake_attempts: AtomicUsize,
    sent_lastminute_handshake: AtomicBool,
    need_another_keepalive: AtomicBool,

    retransmit_handshake: Timer,
    send_keepalive: Timer,
    send_persistent_keepalive: Timer,
    zero_key_material: Timer,
    new_handshake: Timer,
}

impl Timers {
    #[inline(always)]
    fn need_another_keepalive(&self) -> bool {
        self.need_another_keepalive.swap(false, Ordering::SeqCst)
    }
}

impl<T: Tun, B: UDP> PeerInner<T, B> {
    pub fn get_keepalive_interval(&self) -> u64 {
        self.timers().keepalive_interval
    }

    pub fn stop_timers(&self) {
        // take a write lock preventing simultaneous timer events or "start_timers" call
        let mut timers = self.timers_mut();

        // set flag to prevent future timer events
        if !timers.enabled {
            return;
        }
        timers.enabled = false;

        // stop all pending timers
        timers.retransmit_handshake.stop();
        timers.send_keepalive.stop();
        timers.send_persistent_keepalive.stop();
        timers.zero_key_material.stop();
        timers.new_handshake.stop();

        // reset all timer state
        timers.handshake_attempts.store(0, Ordering::SeqCst);
        timers
            .sent_lastminute_handshake
            .store(false, Ordering::SeqCst);
        timers.need_another_keepalive.store(false, Ordering::SeqCst);
    }

    pub fn start_timers(&self) {
        // take a write lock preventing simultaneous "stop_timers" call
        let mut timers = self.timers_mut();

        // set flag to reenable timer events
        if timers.enabled {
            return;
        }
        timers.enabled = true;

        // start send_persistent_keepalive
        if timers.keepalive_interval > 0 {
            timers
                .send_persistent_keepalive
                .start(Duration::from_secs(timers.keepalive_interval));
        }
    }

    /* should be called after an authenticated data packet is sent */
    pub fn timers_data_sent(&self) {
        let timers = self.timers();
        if timers.enabled {
            timers
                .new_handshake
                .start(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
        }
    }

    /* should be called after an authenticated data packet is received */
    pub fn timers_data_received(&self) {
        let timers = self.timers();
        if timers.enabled && !timers.send_keepalive.start(KEEPALIVE_TIMEOUT) {
            timers.need_another_keepalive.store(true, Ordering::SeqCst)
        }
    }

    /* Should be called after any type of authenticated packet is sent, whether:
     * - keepalive
     * - data
     * - handshake
     */
    pub fn timers_any_authenticated_packet_sent(&self) {
        let timers = self.timers();
        if timers.enabled {
            timers.send_keepalive.stop()
        }
    }

    /* Should be called after any type of authenticated packet is received, whether:
     * - keepalive
     * - data
     * - handshake
     */
    pub fn timers_any_authenticated_packet_received(&self) {
        let timers = self.timers();
        if timers.enabled {
            timers.new_handshake.stop();
        }
    }

    /* Should be called after a handshake initiation message is sent. */
    pub fn timers_handshake_initiated(&self) {
        let timers = self.timers();
        if timers.enabled {
            timers.send_keepalive.stop();
            timers.retransmit_handshake.reset(REKEY_TIMEOUT);
        }
    }

    /* Should be called after a handshake response message is received and processed
     * or when getting key confirmation via the first data message.
     */
    pub fn timers_handshake_complete(&self) {
        let timers = self.timers();
        if timers.enabled {
            timers.retransmit_handshake.stop();
            timers.handshake_attempts.store(0, Ordering::SeqCst);
            timers
                .sent_lastminute_handshake
                .store(false, Ordering::SeqCst);
            *self.walltime_last_handshake.lock() = Some(SystemTime::now());
        }
    }

    /* Should be called after an ephemeral key is created, which is before sending a
     * handshake response or after receiving a handshake response.
     */
    pub fn timers_session_derived(&self) {
        let timers = self.timers();
        if timers.enabled {
            timers.zero_key_material.reset(REJECT_AFTER_TIME * 3);
        }
    }

    /* Should be called before a packet with authentication, whether
     * keepalive, data, or handshake is sent, or after one is received.
     */
    pub fn timers_any_authenticated_packet_traversal(&self) {
        let timers = self.timers();
        if timers.enabled && timers.keepalive_interval > 0 {
            // push persistent_keepalive into the future
            timers
                .send_persistent_keepalive
                .reset(Duration::from_secs(timers.keepalive_interval));
        }
    }

    fn timers_set_retransmit_handshake(&self) {
        let timers = self.timers();
        if timers.enabled {
            timers.retransmit_handshake.reset(REKEY_TIMEOUT);
        }
    }

    /* Called after a handshake worker sends a handshake initiation to the peer
     */
    pub fn sent_handshake_initiation(&self) {
        *self.last_handshake_sent.lock() = Instant::now();
        self.timers_handshake_initiated();
        self.timers_set_retransmit_handshake();
        self.timers_any_authenticated_packet_traversal();
        self.timers_any_authenticated_packet_sent();
    }

    pub fn sent_handshake_response(&self) {
        *self.last_handshake_sent.lock() = Instant::now();
        self.timers_any_authenticated_packet_traversal();
        self.timers_any_authenticated_packet_sent();
    }

    pub fn set_persistent_keepalive_interval(&self, secs: u64) {
        let mut timers = self.timers_mut();

        // update the stored keepalive_interval
        timers.keepalive_interval = secs;

        // stop the keepalive timer with the old interval
        timers.send_persistent_keepalive.stop();

        // restart the persistent_keepalive timer with the new interval
        if secs > 0 && timers.enabled {
            timers
                .send_persistent_keepalive
                .start(Duration::from_secs(secs));
        }
    }

    fn packet_send_queued_handshake_initiation(&self, is_retry: bool) {
        if !is_retry {
            self.timers().handshake_attempts.store(0, Ordering::SeqCst);
        }
        self.packet_send_handshake_initiation();
    }
}

impl Timers {
    pub fn new<T: Tun, B: UDP>(runner: &Runner, running: bool, peer: Peer<T, B>) -> Timers {
        // create a timer instance for the provided peer
        Timers {
            enabled: running,
            keepalive_interval: 0, // disabled
            need_another_keepalive: AtomicBool::new(false),
            sent_lastminute_handshake: AtomicBool::new(false),
            handshake_attempts: AtomicUsize::new(0),
            retransmit_handshake: {
                let peer = peer.clone();
                runner.timer(move || {
                    // ignore if timers are disabled
                    let timers = peer.timers();
                    if !timers.enabled {
                        return;
                    }

                    // check if handshake attempts remaining
                    let attempts = peer
                        .timers()
                        .handshake_attempts
                        .fetch_add(1, Ordering::SeqCst);
                    if attempts > MAX_TIMER_HANDSHAKES {
                        debug!(
                            "Handshake for peer {} did not complete after {} attempts, giving up",
                            peer,
                            attempts + 1
                        );
                        timers.send_keepalive.stop();
                        timers.zero_key_material.start(REJECT_AFTER_TIME * 3);
                        peer.router.purge_staged_packets();
                    } else {
                        debug!(
                            "Handshake for {} did not complete after {} seconds, retrying (try {})",
                            peer,
                            REKEY_TIMEOUT.as_secs(),
                            attempts
                        );
                        timers.retransmit_handshake.reset(REKEY_TIMEOUT);
                        peer.router.clear_src();
                        peer.packet_send_queued_handshake_initiation(true);
                    }
                })
            },
            send_keepalive: {
                let peer = peer.clone();
                runner.timer(move || {
                    // ignore if timers are disabled
                    let timers = peer.timers();
                    if !timers.enabled {
                        return;
                    }

                    peer.router.send_keepalive();
                    if timers.need_another_keepalive() {
                        timers.send_keepalive.start(KEEPALIVE_TIMEOUT);
                    }
                })
            },
            new_handshake: {
                let peer = peer.clone();
                runner.timer(move || {
                    debug!(
                        "Retrying handshake with {} because we stopped hearing back after {} seconds",
                        peer,
                        (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT).as_secs()
                    );
                    peer.router.clear_src();
                    peer.packet_send_queued_handshake_initiation(false);
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
                    let timers = peer.timers();
                    if timers.enabled && timers.keepalive_interval > 0 {
                        peer.router.send_keepalive();
                        timers.send_keepalive.stop();
                        timers
                            .send_persistent_keepalive
                            .start(Duration::from_secs(timers.keepalive_interval));
                    }
                })
            },
        }
    }

    pub fn dummy(runner: &Runner) -> Timers {
        Timers {
            enabled: false,
            keepalive_interval: 0,
            need_another_keepalive: AtomicBool::new(false),
            sent_lastminute_handshake: AtomicBool::new(false),
            handshake_attempts: AtomicUsize::new(0),
            retransmit_handshake: runner.timer(|| {}),
            new_handshake: runner.timer(|| {}),
            send_keepalive: runner.timer(|| {}),
            send_persistent_keepalive: runner.timer(|| {}),
            zero_key_material: runner.timer(|| {}),
        }
    }
}

/* Instance of the router callbacks */

pub struct Events<T, B>(PhantomData<(T, B)>);

impl<T: Tun, B: UDP> Callbacks for Events<T, B> {
    type Opaque = Arc<PeerInner<T, B>>;

    /* Called after the router encrypts a transport message destined for the peer.
     * This method is called, even if the encrypted payload is empty (keepalive)
     */
    #[inline(always)]
    fn send(peer: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>, counter: u64) {
        // update timers and stats

        peer.timers_any_authenticated_packet_traversal();
        peer.timers_any_authenticated_packet_sent();
        peer.tx_bytes.fetch_add(size as u64, Ordering::Relaxed);
        if size > message_data_len(0) && sent {
            peer.timers_data_sent();
        }

        // keep_key_fresh

        fn keep_key_fresh(keypair: &Arc<KeyPair>, counter: u64) -> bool {
            counter > REKEY_AFTER_MESSAGES
                || (keypair.initiator && Instant::now() - keypair.birth > REKEY_AFTER_TIME)
        }

        if keep_key_fresh(keypair, counter) {
            peer.packet_send_queued_handshake_initiation(false);
        }
    }

    /* Called after the router successfully decrypts a transport message from a peer.
     * This method is called, even if the decrypted packet is:
     *
     * - A keepalive
     * - A malformed IP packet
     * - Fails to cryptkey route
     */
    #[inline(always)]
    fn recv(peer: &Self::Opaque, size: usize, sent: bool, keypair: &Arc<KeyPair>) {
        // update timers and stats

        peer.timers_any_authenticated_packet_traversal();
        peer.timers_any_authenticated_packet_received();
        peer.rx_bytes.fetch_add(size as u64, Ordering::Relaxed);
        if size > 0 && sent {
            peer.timers_data_received();
        }

        // keep_key_fresh

        #[inline(always)]
        fn keep_key_fresh(keypair: &Arc<KeyPair>) -> bool {
            Instant::now() - keypair.birth > REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
        }

        if keep_key_fresh(keypair)
            && !peer
                .timers()
                .sent_lastminute_handshake
                .swap(true, Ordering::Acquire)
        {
            peer.packet_send_queued_handshake_initiation(false);
        }
    }

    /* Called every time the router detects that a key is required,
     * but no valid key-material is available for the particular peer.
     *
     * The message is called continuously
     * (e.g. for every packet that must be encrypted, until a key becomes available)
     */
    #[inline(always)]
    fn need_key(peer: &Self::Opaque) {
        peer.packet_send_queued_handshake_initiation(false);
    }

    #[inline(always)]
    fn key_confirmed(peer: &Self::Opaque) {
        peer.timers_handshake_complete();
    }
}
