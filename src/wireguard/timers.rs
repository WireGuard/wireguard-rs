use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use log::{debug, info};
use hjul::{Runner, Timer};

use super::constants::*;
use super::router::{message_data_len, Callbacks};
use super::wireguard::{Peer, PeerInner};
use super::{bind, tun};

use super::types::KeyPair;

pub struct Timers {
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

impl<B: bind::Bind> PeerInner<B> {
    /* should be called after an authenticated data packet is sent */
    pub fn timers_data_sent(&self) {
        self.timers()
            .new_handshake
            .start(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
    }

    /* should be called after an authenticated data packet is received */
    pub fn timers_data_received(&self) {
        if !self.timers().send_keepalive.start(KEEPALIVE_TIMEOUT) {
            self.timers()
                .need_another_keepalive
                .store(true, Ordering::SeqCst)
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
        self.timers()
            .sent_lastminute_handshake
            .store(false, Ordering::SeqCst);
        *self.walltime_last_handshake.lock() = SystemTime::now();
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
        let keepalive = self.keepalive.load(Ordering::Acquire);
        if keepalive > 0 {
            // push persistent_keepalive into the future
            self.timers()
                .send_persistent_keepalive
                .reset(Duration::from_secs(keepalive as u64));
        }
    }

    pub fn timers_session_derieved(&self) {
        self.timers().zero_key_material.reset(REJECT_AFTER_TIME * 3);
    }

    /* Called after a handshake worker sends a handshake initiation to the peer
     */
    pub fn sent_handshake_initiation(&self) {
        *self.last_handshake_sent.lock() = Instant::now();
        self.handshake_queued.store(false, Ordering::SeqCst);
        self.timers().retransmit_handshake.reset(REKEY_TIMEOUT);
        self.timers_any_authenticated_packet_traversal();
        self.timers_any_authenticated_packet_sent();
    }

    pub fn sent_handshake_response(&self) {
        *self.last_handshake_sent.lock() = Instant::now();
        self.timers_any_authenticated_packet_traversal();
        self.timers_any_authenticated_packet_sent();
    } 

    fn packet_send_queued_handshake_initiation(&self, is_retry: bool) {
        if !is_retry {
            self.timers().handshake_attempts.store(0, Ordering::SeqCst);
        }
        self.packet_send_handshake_initiation();
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
            need_another_keepalive: AtomicBool::new(false),
            sent_lastminute_handshake: AtomicBool::new(false),
            handshake_attempts: AtomicUsize::new(0),
            retransmit_handshake: {
                let peer = peer.clone();
                runner.timer(move || {
                    let attempts = peer.timers().handshake_attempts.fetch_add(1, Ordering::SeqCst);
                    if attempts > MAX_TIMER_HANDSHAKES {
                        debug!(
                            "Handshake for peer {} did not complete after {} attempts, giving up",
                            peer,
                            attempts + 1
                        );
                        peer.router.purge_staged_packets();
                        peer.timers().send_keepalive.stop();
                        peer.timers().zero_key_material.start(REJECT_AFTER_TIME * 3);
                    } else {
                        debug!(
                            "Handshake for {} did not complete after {} seconds, retrying (try {})",
                            peer, 
                            REKEY_TIMEOUT.as_secs(), 
                            attempts
                        );
                        peer.router.clear_src();
                        peer.timers().retransmit_handshake.reset(REKEY_TIMEOUT);
                        peer.packet_send_queued_handshake_initiation(true);
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
                    let keepalive = peer.state.keepalive.load(Ordering::Acquire);
                    if keepalive > 0 {
                        peer.router.send_keepalive();
                        peer.timers().send_keepalive.stop();
                        peer.timers()
                            .send_persistent_keepalive
                            .start(Duration::from_secs(keepalive as u64));
                    }
                })
            },
        }
    }

    pub fn updated_persistent_keepalive(&self, keepalive: usize) {
        if keepalive > 0 {
            self.send_persistent_keepalive
                .reset(Duration::from_secs(keepalive as u64));
        }
    }

    pub fn dummy(runner: &Runner) -> Timers {
        Timers {
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

    pub fn handshake_sent(&self) {
        self.send_keepalive.stop();
    }
}

/* Instance of the router callbacks */

pub struct Events<T, B>(PhantomData<(T, B)>);

impl<T: tun::Tun, B: bind::Bind> Callbacks for Events<T, B> {
    type Opaque = Arc<PeerInner<B>>;

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

        if keep_key_fresh(keypair) && !peer.timers().sent_lastminute_handshake.swap(true, Ordering::Acquire) {
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
        peer.timers().retransmit_handshake.stop();
    }
}
