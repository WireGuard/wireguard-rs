use std::sync::mpsc::Receiver;
use std::sync::Arc;

use futures::sync::oneshot;
use futures::*;

use log::{debug, trace};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

use std::sync::atomic::Ordering;
use zerocopy::{AsBytes, LayoutVerified};

use super::device::{DecryptionState, DeviceInner};
use super::messages::{TransportHeader, TYPE_TRANSPORT};
use super::peer::PeerInner;
use super::types::Callbacks;

use super::REJECT_AFTER_MESSAGES;

use super::super::types::KeyPair;
use super::super::{tun, udp, Endpoint};

pub const SIZE_TAG: usize = 16;

pub struct JobEncryption {
    pub msg: Vec<u8>,
    pub keypair: Arc<KeyPair>,
    pub counter: u64,
}

pub struct JobDecryption {
    pub msg: Vec<u8>,
    pub keypair: Arc<KeyPair>,
}

pub enum JobParallel {
    Encryption(oneshot::Sender<JobEncryption>, JobEncryption),
    Decryption(oneshot::Sender<Option<JobDecryption>>, JobDecryption),
}

#[allow(type_alias_bounds)]
pub type JobInbound<E, C, T, B: udp::Writer<E>> = (
    Arc<DecryptionState<E, C, T, B>>,
    E,
    oneshot::Receiver<Option<JobDecryption>>,
);

pub type JobOutbound = oneshot::Receiver<JobEncryption>;

/* TODO: Replace with run-queue
 */
pub fn worker_inbound<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
    device: Arc<DeviceInner<E, C, T, B>>, // related device
    peer: Arc<PeerInner<E, C, T, B>>,     // related peer
    receiver: Receiver<JobInbound<E, C, T, B>>,
) {
    loop {
        // fetch job
        let (state, endpoint, rx) = match receiver.recv() {
            Ok(v) => v,
            _ => {
                return;
            }
        };
        debug!("inbound worker: obtained job");

        // wait for job to complete
        let _ = rx
            .map(|buf| {
                debug!("inbound worker: job complete");
                if let Some(buf) = buf {
                    // cast transport header
                    let (header, packet): (LayoutVerified<&[u8], TransportHeader>, &[u8]) =
                        match LayoutVerified::new_from_prefix(&buf.msg[..]) {
                            Some(v) => v,
                            None => {
                                debug!("inbound worker: failed to parse message");
                                return;
                            }
                        };

                    debug_assert!(
                        packet.len() >= CHACHA20_POLY1305.tag_len(),
                        "this should be checked earlier in the pipeline (decryption should fail)"
                    );

                    // check for replay
                    if !state.protector.lock().update(header.f_counter.get()) {
                        debug!("inbound worker: replay detected");
                        return;
                    }

                    // check for confirms key
                    if !state.confirmed.swap(true, Ordering::SeqCst) {
                        debug!("inbound worker: message confirms key");
                        peer.confirm_key(&state.keypair);
                    }

                    // update endpoint
                    *peer.endpoint.lock() = Some(endpoint);

                    // calculate length of IP packet + padding
                    let length = packet.len() - SIZE_TAG;
                    debug!("inbound worker: plaintext length = {}", length);

                    // check if should be written to TUN
                    let mut sent = false;
                    if length > 0 {
                        if let Some(inner_len) = device.table.check_route(&peer, &packet[..length])
                        {
                            // TODO: Consider moving the cryptkey route check to parallel decryption worker
                            debug_assert!(inner_len <= length, "should be validated earlier");
                            if inner_len <= length {
                                sent = match device.inbound.write(&packet[..inner_len]) {
                                    Err(e) => {
                                        debug!("failed to write inbound packet to TUN: {:?}", e);
                                        false
                                    }
                                    Ok(_) => true,
                                }
                            }
                        }
                    } else {
                        debug!("inbound worker: received keepalive")
                    }

                    // trigger callback
                    C::recv(&peer.opaque, buf.msg.len(), sent, &buf.keypair);
                } else {
                    debug!("inbound worker: authentication failure")
                }
            })
            .wait();
    }
}

/* TODO: Replace with run-queue
 */
pub fn worker_outbound<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
    peer: Arc<PeerInner<E, C, T, B>>,
    receiver: Receiver<JobOutbound>,
) {
    loop {
        // fetch job
        let rx = match receiver.recv() {
            Ok(v) => v,
            _ => {
                return;
            }
        };
        debug!("outbound worker: obtained job");

        // wait for job to complete
        let _ = rx
            .map(|buf| {
                debug!("outbound worker: job complete");

                // send to peer
                let xmit = peer.send(&buf.msg[..]).is_ok();

                // trigger callback
                C::send(&peer.opaque, buf.msg.len(), xmit, &buf.keypair, buf.counter);
            })
            .wait();
    }
}

pub fn worker_parallel(receiver: Receiver<JobParallel>) {
    loop {
        // fetch next job
        let job = match receiver.recv() {
            Err(_) => {
                return;
            }
            Ok(val) => val,
        };
        trace!("parallel worker: obtained job");

        // handle job
        match job {
            JobParallel::Encryption(tx, mut job) => {
                job.msg.extend([0u8; SIZE_TAG].iter());

                // cast to header (should never fail)
                let (mut header, body): (LayoutVerified<&mut [u8], TransportHeader>, &mut [u8]) =
                    LayoutVerified::new_from_prefix(&mut job.msg[..])
                        .expect("earlier code should ensure that there is ample space");

                // set header fields
                debug_assert!(
                    job.counter < REJECT_AFTER_MESSAGES,
                    "should be checked when assigning counters"
                );
                header.f_type.set(TYPE_TRANSPORT);
                header.f_receiver.set(job.keypair.send.id);
                header.f_counter.set(job.counter);

                // create a nonce object
                let mut nonce = [0u8; 12];
                debug_assert_eq!(nonce.len(), CHACHA20_POLY1305.nonce_len());
                nonce[4..].copy_from_slice(header.f_counter.as_bytes());
                let nonce = Nonce::assume_unique_for_key(nonce);

                // do the weird ring AEAD dance
                let key = LessSafeKey::new(
                    UnboundKey::new(&CHACHA20_POLY1305, &job.keypair.send.key[..]).unwrap(),
                );

                // encrypt content of transport message in-place
                let end = body.len() - SIZE_TAG;
                let tag = key
                    .seal_in_place_separate_tag(nonce, Aad::empty(), &mut body[..end])
                    .unwrap();

                // append tag
                body[end..].copy_from_slice(tag.as_ref());

                // pass ownership
                let _ = tx.send(job);
            }
            JobParallel::Decryption(tx, mut job) => {
                // cast to header (could fail)
                let layout: Option<(LayoutVerified<&mut [u8], TransportHeader>, &mut [u8])> =
                    LayoutVerified::new_from_prefix(&mut job.msg[..]);

                let _ = tx.send(match layout {
                    Some((header, body)) => {
                        debug_assert_eq!(
                            header.f_type.get(),
                            TYPE_TRANSPORT,
                            "type and reserved bits should be checked by message de-multiplexer"
                        );
                        if header.f_counter.get() < REJECT_AFTER_MESSAGES {
                            // create a nonce object
                            let mut nonce = [0u8; 12];
                            debug_assert_eq!(nonce.len(), CHACHA20_POLY1305.nonce_len());
                            nonce[4..].copy_from_slice(header.f_counter.as_bytes());
                            let nonce = Nonce::assume_unique_for_key(nonce);

                            // do the weird ring AEAD dance
                            let key = LessSafeKey::new(
                                UnboundKey::new(&CHACHA20_POLY1305, &job.keypair.recv.key[..])
                                    .unwrap(),
                            );

                            // attempt to open (and authenticate) the body
                            match key.open_in_place(nonce, Aad::empty(), body) {
                                Ok(_) => Some(job),
                                Err(_) => None,
                            }
                        } else {
                            None
                        }
                    }
                    None => None,
                });
            }
        }
    }
}
