use super::constants::MAX_INORDER_CONSUME;
use super::device::DecryptionState;
use super::device::Device;
use super::messages::TransportHeader;
use super::peer::Peer;
use super::pool::*;
use super::runq::RunQueue;
use super::types::Callbacks;
use super::{tun, udp, Endpoint};

use crossbeam_channel::Receiver;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use zerocopy::{AsBytes, LayoutVerified};

use std::mem;
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub const SIZE_TAG: usize = 16;

pub struct Inbound<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    msg: Vec<u8>,
    failed: bool,
    state: Arc<DecryptionState<E, C, T, B>>,
    endpoint: Option<E>,
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Inbound<E, C, T, B> {
    pub fn new(
        msg: Vec<u8>,
        state: Arc<DecryptionState<E, C, T, B>>,
        endpoint: E,
    ) -> Inbound<E, C, T, B> {
        Inbound {
            msg,
            state,
            failed: false,
            endpoint: Some(endpoint),
        }
    }
}

#[inline(always)]
pub fn parallel<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
    device: Device<E, C, T, B>,
    receiver: Receiver<Job<Peer<E, C, T, B>, Inbound<E, C, T, B>>>,
) {
    // run queue to schedule
    fn queue<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
        device: &Device<E, C, T, B>,
    ) -> &RunQueue<Peer<E, C, T, B>> {
        &device.run_inbound
    }

    // parallel work to apply
    fn work<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
        peer: &Peer<E, C, T, B>,
        body: &mut Inbound<E, C, T, B>,
    ) {
        log::trace!("worker, parallel section, obtained job");

        // cast to header followed by payload
        let (header, packet): (LayoutVerified<&mut [u8], TransportHeader>, &mut [u8]) =
            match LayoutVerified::new_from_prefix(&mut body.msg[..]) {
                Some(v) => v,
                None => {
                    log::debug!("inbound worker: failed to parse message");
                    return;
                }
            };

        // authenticate and decrypt payload
        {
            // create nonce object
            let mut nonce = [0u8; 12];
            debug_assert_eq!(nonce.len(), CHACHA20_POLY1305.nonce_len());
            nonce[4..].copy_from_slice(header.f_counter.as_bytes());
            let nonce = Nonce::assume_unique_for_key(nonce);

            // do the weird ring AEAD dance
            let key = LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &body.state.keypair.recv.key[..]).unwrap(),
            );

            // attempt to open (and authenticate) the body
            match key.open_in_place(nonce, Aad::empty(), packet) {
                Ok(_) => (),
                Err(_) => {
                    // fault and return early
                    log::trace!("inbound worker: authentication failure");
                    body.failed = true;
                    return;
                }
            }
        }

        // cryptokey route and strip padding
        let inner_len = {
            let length = packet.len() - SIZE_TAG;
            if length > 0 {
                peer.device.table.check_route(&peer, &packet[..length])
            } else {
                Some(0)
            }
        };

        // truncate to remove tag
        match inner_len {
            None => {
                log::trace!("inbound worker: cryptokey routing failed");
                body.failed = true;
            }
            Some(len) => {
                log::trace!(
                    "inbound worker: good route, length = {} {}",
                    len,
                    if len == 0 { "(keepalive)" } else { "" }
                );
                body.msg.truncate(mem::size_of::<TransportHeader>() + len);
            }
        }
    }

    worker_parallel(device, |dev| &dev.run_inbound, receiver, work)
}

#[inline(always)]
pub fn sequential<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
    device: Device<E, C, T, B>,
) {
    // sequential work to apply
    fn work<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
        peer: &Peer<E, C, T, B>,
        body: &mut Inbound<E, C, T, B>,
    ) {
        log::trace!("worker, sequential section, obtained job");

        // decryption failed, return early
        if body.failed {
            log::trace!("job faulted, remove from queue and ignore");
            return;
        }

        // cast transport header
        let (header, packet): (LayoutVerified<&[u8], TransportHeader>, &[u8]) =
            match LayoutVerified::new_from_prefix(&body.msg[..]) {
                Some(v) => v,
                None => {
                    log::debug!("inbound worker: failed to parse message");
                    return;
                }
            };

        // check for replay
        if !body.state.protector.lock().update(header.f_counter.get()) {
            log::debug!("inbound worker: replay detected");
            return;
        }

        // check for confirms key
        if !body.state.confirmed.swap(true, Ordering::SeqCst) {
            log::debug!("inbound worker: message confirms key");
            peer.confirm_key(&body.state.keypair);
        }

        // update endpoint
        *peer.endpoint.lock() = body.endpoint.take();

        // check if should be written to TUN
        let mut sent = false;
        if packet.len() > 0 {
            sent = match peer.device.inbound.write(&packet[..]) {
                Err(e) => {
                    log::debug!("failed to write inbound packet to TUN: {:?}", e);
                    false
                }
                Ok(_) => true,
            }
        } else {
            log::debug!("inbound worker: received keepalive")
        }

        // trigger callback
        C::recv(&peer.opaque, body.msg.len(), sent, &body.state.keypair);
    }

    // handle message from the peers inbound queue
    device.run_inbound.run(|peer| {
        peer.inbound
            .handle(|body| work(&peer, body), MAX_INORDER_CONSUME)
    });
}
