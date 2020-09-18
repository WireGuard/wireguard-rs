use std::sync::atomic::Ordering;
use std::time::Instant;

use byteorder::{ByteOrder, LittleEndian};
use crossbeam_channel::Receiver;
use log::debug;
use rand::rngs::OsRng;
use x25519_dalek::PublicKey;

// IO traits
use super::Endpoint;

use super::tun::Reader as TunReader;
use super::tun::Tun;

use super::udp::Reader as UDPReader;
use super::udp::UDP;

// constants
use super::constants::{
    DURATION_UNDER_LOAD, MAX_QUEUED_INCOMING_HANDSHAKES, MESSAGE_PADDING_MULTIPLE,
    THRESHOLD_UNDER_LOAD,
};
use super::handshake::MAX_HANDSHAKE_MSG_SIZE;
use super::handshake::{TYPE_COOKIE_REPLY, TYPE_INITIATION, TYPE_RESPONSE};
use super::router::{CAPACITY_MESSAGE_POSTFIX, SIZE_MESSAGE_PREFIX, TYPE_TRANSPORT};

use super::wireguard::WireGuard;

pub enum HandshakeJob<E> {
    Message(Vec<u8>, E),
    New(PublicKey),
}

/* Returns the padded length of a message:
 *
 * # Arguments
 *
 * - `size` : Size of unpadded message
 * - `mtu` : Maximum transmission unit of the device
 *
 * # Returns
 *
 * The padded length (always less than or equal to the MTU)
 */
#[inline(always)]
const fn padding(size: usize, mtu: usize) -> usize {
    #[inline(always)]
    const fn min(a: usize, b: usize) -> usize {
        let m = (a < b) as usize;
        a * m + (1 - m) * b
    }
    let pad = MESSAGE_PADDING_MULTIPLE;
    min(mtu, size + (pad - size % pad) % pad)
}

pub fn tun_worker<T: Tun, B: UDP>(wg: &WireGuard<T, B>, reader: T::Reader) {
    loop {
        // create vector big enough for any transport message (based on MTU)
        let mtu = wg.mtu.load(Ordering::Relaxed);
        let size = mtu + SIZE_MESSAGE_PREFIX + 1;
        let mut msg: Vec<u8> = vec![0; size + CAPACITY_MESSAGE_POSTFIX];

        // read a new IP packet
        let payload = match reader.read(&mut msg[..], SIZE_MESSAGE_PREFIX) {
            Ok(payload) => payload,
            Err(e) => {
                debug!("TUN worker, failed to read from tun device: {}", e);
                break;
            }
        };
        debug!("TUN worker, IP packet of {} bytes (MTU = {})", payload, mtu);

        // check if device is down
        if mtu == 0 {
            continue;
        }

        // truncate padding
        let padded = padding(payload, mtu);
        log::trace!(
            "TUN worker, payload length = {}, padded length = {}",
            payload,
            padded
        );
        msg.truncate(SIZE_MESSAGE_PREFIX + padded);
        debug_assert!(padded <= mtu);
        debug_assert_eq!(
            if padded < mtu {
                (msg.len() - SIZE_MESSAGE_PREFIX) % MESSAGE_PADDING_MULTIPLE
            } else {
                0
            },
            0
        );

        // crypt-key route
        let e = wg.router.send(msg);
        debug!("TUN worker, router returned {:?}", e);
    }
}

pub fn udp_worker<T: Tun, B: UDP>(wg: &WireGuard<T, B>, reader: B::Reader) {
    loop {
        // create vector big enough for any message given current MTU
        let mtu = wg.mtu.load(Ordering::Relaxed);
        let size = mtu + MAX_HANDSHAKE_MSG_SIZE;
        let mut msg: Vec<u8> = vec![0; size];

        // read UDP packet into vector
        let (size, src) = match reader.read(&mut msg) {
            Err(e) => {
                debug!("Bind reader closed with {}", e);
                return;
            }
            Ok(v) => v,
        };
        msg.truncate(size);

        // TODO: start device down
        if mtu == 0 {
            continue;
        }

        // message type de-multiplexer
        if msg.len() < std::mem::size_of::<u32>() {
            continue;
        }
        match LittleEndian::read_u32(&msg[..]) {
            TYPE_COOKIE_REPLY | TYPE_INITIATION | TYPE_RESPONSE => {
                debug!("{} : reader, received handshake message", wg);
                wg.pending.fetch_add(1, Ordering::SeqCst);
                wg.queue.send(HandshakeJob::Message(msg, src));
            }
            TYPE_TRANSPORT => {
                debug!("{} : reader, received transport message", wg);

                // transport message
                let _ = wg.router.recv(src, msg).map_err(|e| {
                    debug!("Failed to handle incoming transport message: {}", e);
                });
            }
            _ => (),
        }
    }
}

pub fn handshake_worker<T: Tun, B: UDP>(
    wg: &WireGuard<T, B>,
    rx: Receiver<HandshakeJob<B::Endpoint>>,
) {
    debug!("{} : handshake worker, started", wg);

    // process elements from the handshake queue
    for job in rx {
        // check if under load
        let mut under_load = false;
        let job: HandshakeJob<B::Endpoint> = job;
        let pending = wg.pending.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(pending < MAX_QUEUED_INCOMING_HANDSHAKES + (1 << 16));

        // immediate go under load if too many handshakes pending
        if pending > THRESHOLD_UNDER_LOAD {
            log::trace!("{} : handshake worker, under load (above threshold)", wg);
            *wg.last_under_load.lock() = Instant::now();
            under_load = true;
        }

        // remain under load for DURATION_UNDER_LOAD
        if !under_load {
            let elapsed = wg.last_under_load.lock().elapsed();
            if DURATION_UNDER_LOAD >= elapsed {
                log::trace!("{} : handshake worker, under load (recent)", wg);
                under_load = true;
            }
        }

        // de-multiplex staged handshake jobs and handshake messages
        match job {
            HandshakeJob::Message(msg, mut src) => {
                // process message
                let device = wg.peers.read();
                match device.process(
                    &mut OsRng,
                    &msg[..],
                    if under_load {
                        Some(src.into_address())
                    } else {
                        None
                    },
                ) {
                    Ok((peer, resp, keypair)) => {
                        // send response (might be cookie reply or handshake response)
                        let mut resp_len: u64 = 0;
                        if let Some(msg) = resp {
                            resp_len = msg.len() as u64;
                            // TODO: consider a more elegant solution for accessing the bind
                            let _ = wg.router.send_raw(&msg[..], &mut src).map_err(|e| {
                                debug!(
                                    "{} : handshake worker, failed to send response, error = {}",
                                    wg, e
                                );
                            });
                        }

                        // update peer state
                        if let Some(peer) = peer {
                            // authenticated handshake packet received

                            // add to rx_bytes and tx_bytes
                            let req_len = msg.len() as u64;
                            peer.opaque().rx_bytes.fetch_add(req_len, Ordering::Relaxed);
                            peer.opaque()
                                .tx_bytes
                                .fetch_add(resp_len, Ordering::Relaxed);

                            // update endpoint
                            peer.set_endpoint(src);

                            if resp_len > 0 {
                                // update timers after sending handshake response
                                debug!("{} : handshake worker, handshake response sent", wg);
                                peer.opaque().sent_handshake_response();
                            } else {
                                // update timers after receiving handshake response
                                debug!(
                                    "{} : handshake worker, handshake response was received",
                                    wg
                                );
                                peer.opaque().timers_handshake_complete();
                            }

                            // add any new keypair to peer
                            if let Some(kp) = keypair {
                                debug!("{} : handshake worker, new keypair for {}", wg, peer);

                                // this means that a handshake response was processed or sent
                                peer.opaque().timers_session_derived();

                                // free any unused ids
                                for id in peer.add_keypair(kp) {
                                    device.release(id);
                                }
                            };
                        }
                    }
                    Err(e) => debug!("{} : handshake worker, error = {:?}", wg, e),
                }
            }
            HandshakeJob::New(pk) => {
                if let Some(peer) = wg.peers.read().get(&pk) {
                    debug!(
                        "{} : handshake worker, new handshake requested for {}",
                        wg, peer
                    );
                    let device = wg.peers.read();
                    let _ = device.begin(&mut OsRng, &pk).map(|msg| {
                        let _ = peer.send_raw(&msg[..]).map_err(|e| {
                            debug!("{} : handshake worker, failed to send handshake initiation, error = {}", wg, e)
                        });
                        peer.opaque().sent_handshake_initiation();
                    });
                    peer.opaque()
                        .handshake_queued
                        .store(false, Ordering::SeqCst);
                }
            }
        }
    }
}
