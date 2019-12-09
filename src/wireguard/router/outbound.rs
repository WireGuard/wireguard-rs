use super::device::Device;
use super::messages::{TransportHeader, TYPE_TRANSPORT};
use super::peer::Peer;
use super::pool::*;
use super::types::Callbacks;
use super::KeyPair;
use super::REJECT_AFTER_MESSAGES;
use super::{tun, udp, Endpoint};

use std::sync::mpsc::Receiver;
use std::sync::Arc;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use zerocopy::{AsBytes, LayoutVerified};

pub const SIZE_TAG: usize = 16;

pub struct Outbound {
    msg: Vec<u8>,
    keypair: Arc<KeyPair>,
    counter: u64,
}

impl Outbound {
    pub fn new(msg: Vec<u8>, keypair: Arc<KeyPair>, counter: u64) -> Outbound {
        Outbound {
            msg,
            keypair,
            counter,
        }
    }
}

#[inline(always)]
pub fn parallel<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
    device: Device<E, C, T, B>,
    receiver: Receiver<Job<Peer<E, C, T, B>, Outbound>>,
) {
    fn work<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
        _peer: &Peer<E, C, T, B>,
        body: &mut Outbound,
    ) {
        log::trace!("worker, parallel section, obtained job");

        // make space for the tag
        body.msg.extend([0u8; SIZE_TAG].iter());

        // cast to header (should never fail)
        let (mut header, packet): (LayoutVerified<&mut [u8], TransportHeader>, &mut [u8]) =
            LayoutVerified::new_from_prefix(&mut body.msg[..])
                .expect("earlier code should ensure that there is ample space");

        // set header fields
        debug_assert!(
            body.counter < REJECT_AFTER_MESSAGES,
            "should be checked when assigning counters"
        );
        header.f_type.set(TYPE_TRANSPORT);
        header.f_receiver.set(body.keypair.send.id);
        header.f_counter.set(body.counter);

        // create a nonce object
        let mut nonce = [0u8; 12];
        debug_assert_eq!(nonce.len(), CHACHA20_POLY1305.nonce_len());
        nonce[4..].copy_from_slice(header.f_counter.as_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce);

        // do the weird ring AEAD dance
        let key = LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &body.keypair.send.key[..]).unwrap(),
        );

        // encrypt content of transport message in-place
        let end = packet.len() - SIZE_TAG;
        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut packet[..end])
            .unwrap();

        // append tag
        packet[end..].copy_from_slice(tag.as_ref());
    }

    worker_parallel(device, |dev| &dev.run_outbound, receiver, work);
}

#[inline(always)]
pub fn sequential<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
    device: Device<E, C, T, B>,
) {
    device.run_outbound.run(|peer| {
        peer.outbound.handle(|body| {
            log::trace!("worker, sequential section, obtained job");

            // send to peer
            let xmit = peer.send(&body.msg[..]).is_ok();

            // trigger callback
            C::send(
                &peer.opaque,
                body.msg.len(),
                xmit,
                &body.keypair,
                body.counter,
            );
        });
    });
}
