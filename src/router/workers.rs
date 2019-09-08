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
use super::messages::TransportHeader;
use super::peer::PeerInner;
use super::types::Callbacks;

use super::ip::*;

use super::super::types::{Bind, Tun};

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
pub type JobInbound<C, T, B: Bind> = (
    Arc<DecryptionState<C, T, B>>,
    B::Endpoint,
    oneshot::Receiver<JobBuffer>,
);

pub type JobOutbound = oneshot::Receiver<JobBuffer>;

#[inline(always)]
fn check_route<C: Callbacks, T: Tun, B: Bind>(
    device: &Arc<DeviceInner<C, T, B>>,
    peer: &Arc<PeerInner<C, T, B>>,
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

pub fn worker_inbound<C: Callbacks, T: Tun, B: Bind>(
    device: Arc<DeviceInner<C, T, B>>, // related device
    peer: Arc<PeerInner<C, T, B>>,     // related peer
    receiver: Receiver<JobInbound<C, T, B>>,
) {
    loop {
        // fetch job
        let (state, endpoint, rx) = match receiver.recv() {
            Ok(v) => v,
            _ => {
                return;
            }
        };

        // wait for job to complete
        let _ = rx
            .map(|buf| {
                if buf.okay {
                    // cast transport header
                    let (header, packet): (LayoutVerified<&[u8], TransportHeader>, &[u8]) =
                        match LayoutVerified::new_from_prefix(&buf.msg[..]) {
                            Some(v) => v,
                            None => {
                                return;
                            }
                        };

                    debug_assert!(
                        packet.len() >= CHACHA20_POLY1305.tag_len(),
                        "this should be checked earlier in the pipeline"
                    );

                    // check for replay
                    if !state.protector.lock().update(header.f_counter.get()) {
                        return;
                    }

                    // check for confirms key
                    if !state.confirmed.swap(true, Ordering::SeqCst) {
                        peer.confirm_key(&state.keypair);
                    }

                    // update endpoint
                    *peer.endpoint.lock() = Some(endpoint);

                    // calculate length of IP packet + padding
                    let length = packet.len() - CHACHA20_POLY1305.nonce_len();

                    // check if should be written to TUN
                    let mut sent = false;
                    if length > 0 {
                        if let Some(inner_len) = check_route(&device, &peer, &packet[..length]) {
                            debug_assert!(inner_len <= length, "should be validated");
                            if inner_len <= length {
                                sent = match device.tun.write(&packet[..inner_len]) {
                                    Err(e) => {
                                        debug!("failed to write inbound packet to TUN: {:?}", e);
                                        false
                                    }
                                    Ok(_) => true,
                                }
                            }
                        }
                    }

                    // trigger callback
                    (device.call_recv)(&peer.opaque, length == 0, sent);
                }
            })
            .wait();
    }
}

pub fn worker_outbound<C: Callbacks, T: Tun, B: Bind>(
    device: Arc<DeviceInner<C, T, B>>, // related device
    peer: Arc<PeerInner<C, T, B>>,     // related peer
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

        // wait for job to complete
        let _ = rx
            .map(|buf| {
                if buf.okay {
                    // write to UDP bind
                    let xmit = if let Some(dst) = peer.endpoint.lock().as_ref() {
                        match device.bind.send(&buf.msg[..], dst) {
                            Err(e) => {
                                debug!("failed to send outbound packet: {:?}", e);
                                false
                            }
                            Ok(_) => true,
                        }
                    } else {
                        false
                    };

                    // trigger callback
                    (device.call_send)(
                        &peer.opaque,
                        buf.msg.len()
                            > CHACHA20_POLY1305.nonce_len() + mem::size_of::<TransportHeader>(),
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

        // cast and check size of packet
        let (header, packet): (LayoutVerified<&[u8], TransportHeader>, &[u8]) =
            match LayoutVerified::new_from_prefix(&buf.msg[..]) {
                Some(v) => v,
                None => continue,
            };

        if packet.len() < CHACHA20_POLY1305.nonce_len() {
            continue;
        }

        // do the weird ring AEAD dance
        let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &buf.key[..]).unwrap());

        // create a nonce object
        let mut nonce = [0u8; 12];
        debug_assert_eq!(nonce.len(), CHACHA20_POLY1305.nonce_len());
        nonce[4..].copy_from_slice(header.f_counter.as_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce);

        match buf.op {
            Operation::Encryption => {
                debug!("worker, process encryption");

                // note: extends the vector to accommodate the tag
                key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf.msg)
                    .unwrap();
                buf.okay = true;
            }
            Operation::Decryption => {
                debug!("worker, process decryption");

                // opening failure is signaled by fault state
                buf.okay = match key.open_in_place(nonce, Aad::empty(), &mut buf.msg) {
                    Ok(_) => true,
                    Err(_) => false,
                };
            }
        }

        // pass ownership to consumer
        let _ = tx.send(buf);
    }
}
