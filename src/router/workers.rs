use std::mem;
use std::sync::mpsc::Receiver;
use std::sync::Arc;

use futures::sync::oneshot;
use futures::*;

use log::debug;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use zerocopy::{AsBytes, LayoutVerified};

use super::device::{DecryptionState, DeviceInner};
use super::messages::{TransportHeader, TYPE_TRANSPORT};
use super::peer::PeerInner;
use super::types::Callbacks;

use super::super::types::{Endpoint, tun, bind};
use super::ip::*;

const SIZE_TAG: usize = 16;

#[derive(PartialEq, Debug)]
pub enum Operation {
    Encryption,
    Decryption,
}

pub struct JobBuffer {
    pub msg: Vec<u8>,  // message buffer (nonce and receiver id set)
    pub key: [u8; 32], // chacha20poly1305 key
    pub okay: bool,    // state of the job
    pub op: Operation, // should be buffer be encrypted / decrypted?
}

pub type JobParallel = (oneshot::Sender<JobBuffer>, JobBuffer);

#[allow(type_alias_bounds)]
pub type JobInbound<E, C, T, B: bind::Writer<E>> = (
    Arc<DecryptionState<E, C, T, B>>,
    E,
    oneshot::Receiver<JobBuffer>,
);

pub type JobOutbound = oneshot::Receiver<JobBuffer>;

#[inline(always)]
fn check_route<E : Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>>(
    device: &Arc<DeviceInner<E, C, T, B>>,
    peer: &Arc<PeerInner<E, C, T, B>>,
    packet: &[u8],
) -> Option<usize> {
    match packet[0] >> 4 {
        VERSION_IP4 => {
            // check length and cast to IPv4 header
            let (header, _): (LayoutVerified<&[u8], IPv4Header>, _) =
                LayoutVerified::new_from_prefix(packet)?;

            // check IPv4 source address
            device
                .ipv4
                .read()
                .longest_match(Ipv4Addr::from(header.f_source))
                .and_then(|(_, _, p)| {
                    if Arc::ptr_eq(p, &peer) {
                        Some(header.f_total_len.get() as usize)
                    } else {
                        None
                    }
                })
        }
        VERSION_IP6 => {
            // check length and cast to IPv6 header
            let (header, _): (LayoutVerified<&[u8], IPv6Header>, _) =
                LayoutVerified::new_from_prefix(packet)?;

            // check IPv6 source address
            device
                .ipv6
                .read()
                .longest_match(Ipv6Addr::from(header.f_source))
                .and_then(|(_, _, p)| {
                    if Arc::ptr_eq(p, &peer) {
                        Some(header.f_len.get() as usize + mem::size_of::<IPv6Header>())
                    } else {
                        None
                    }
                })
        }
        _ => None,
    }
}

pub fn worker_inbound<E : Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>>(
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
                if buf.okay {
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
                        if let Some(inner_len) = check_route(&device, &peer, &packet[..length]) {
                            debug_assert!(inner_len <= length, "should be validated");
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
                    C::recv(&peer.opaque, buf.msg.len(), length == 0, sent);
                } else {
                    debug!("inbound worker: authentication failure")
                }
            })
            .wait();
    }
}

pub fn worker_outbound<E : Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>>(
    device: Arc<DeviceInner<E, C, T, B>>, // related device
    peer: Arc<PeerInner<E, C, T, B>>,     // related peer
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
                if buf.okay {
                    // write to UDP bind
                    let xmit = if let Some(dst) = peer.endpoint.lock().as_ref() {
                        let send : &Option<B> = &*device.outbound.read();
                        if let Some(writer) = send.as_ref() {
                            match writer.write(&buf.msg[..], dst) {
                                Err(e) => {
                                    debug!("failed to send outbound packet: {:?}", e);
                                    false
                                }
                                Ok(_) => true,
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    // trigger callback
                    C::send(
                        &peer.opaque,
                        buf.msg.len(),
                        buf.msg.len() > SIZE_TAG + mem::size_of::<TransportHeader>(),
                        xmit,
                    );
                }
            })
            .wait();
    }
}

pub fn worker_parallel(receiver: Receiver<JobParallel>) {
    loop {
        // fetch next job
        let (tx, mut buf) = match receiver.recv() {
            Err(_) => {
                return;
            }
            Ok(val) => val,
        };
        debug!("parallel worker: obtained job");

        // make space for tag (TODO: consider moving this out)
        if buf.op == Operation::Encryption {
            buf.msg.extend([0u8; SIZE_TAG].iter());
        }

        // cast and check size of packet
        let (mut header, packet): (LayoutVerified<&mut [u8], TransportHeader>, &mut [u8]) =
            match LayoutVerified::new_from_prefix(&mut buf.msg[..]) {
                Some(v) => v,
                None => {
                    debug_assert!(
                        false,
                        "parallel worker: failed to parse message (insufficient size)"
                    );
                    continue;
                }
            };
        debug_assert!(packet.len() >= CHACHA20_POLY1305.tag_len());

        // do the weird ring AEAD dance
        let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &buf.key[..]).unwrap());

        // create a nonce object
        let mut nonce = [0u8; 12];
        debug_assert_eq!(nonce.len(), CHACHA20_POLY1305.nonce_len());
        nonce[4..].copy_from_slice(header.f_counter.as_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce);

        match buf.op {
            Operation::Encryption => {
                debug!("parallel worker: process encryption");

                // set the type field
                header.f_type.set(TYPE_TRANSPORT);

                // encrypt content of transport message in-place
                let end = packet.len() - SIZE_TAG;
                let tag = key
                    .seal_in_place_separate_tag(nonce, Aad::empty(), &mut packet[..end])
                    .unwrap();

                // append tag
                packet[end..].copy_from_slice(tag.as_ref());

                buf.okay = true;
            }
            Operation::Decryption => {
                debug!("parallel worker: process decryption");

                // opening failure is signaled by fault state
                buf.okay = match key.open_in_place(nonce, Aad::empty(), packet) {
                    Ok(_) => true,
                    Err(_) => false,
                };
            }
        }

        // pass ownership to consumer
        let okay = tx.send(buf);
        debug!(
            "parallel worker: passing ownership to sequential worker: {}",
            okay.is_ok()
        );
    }
}
