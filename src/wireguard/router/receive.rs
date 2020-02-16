use super::queue::{Job, Queue};
use super::KeyPair;
use super::types::Callbacks;
use super::peer::Peer;
use super::{REJECT_AFTER_MESSAGES, SIZE_TAG};
use super::messages::{TransportHeader, TYPE_TRANSPORT};
use super::device::DecryptionState;

use super::super::{tun, udp, Endpoint};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::mem;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use zerocopy::{AsBytes, LayoutVerified};
use spin::Mutex;


struct Inner<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    ready: AtomicBool,
    buffer: Mutex<(Option<E>, Vec<u8>)>, // endpoint & ciphertext buffer
    state: Arc<DecryptionState<E, C, T, B>>, // decryption state (keys and replay protector)
}

pub struct ReceiveJob<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>  {
    inner: Arc<Inner<E, C, T, B>>,
}

impl  <E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> ReceiveJob<E, C, T, B> {
    fn new(buffer: Vec<u8>, state: Arc<DecryptionState<E, C, T, B>>, endpoint: E) -> Option<ReceiveJob<E, C, T, B>> {
        // create job
        let inner = Arc::new(Inner{
            ready: AtomicBool::new(false),
            buffer: Mutex::new((Some(endpoint), buffer)),
            state
        });

        // attempt to add to queue
        if state.peer.inbound.push(ReceiveJob{ inner: inner.clone()}) {
            Some(ReceiveJob{inner})
        } else {
            None
        }
        
    }
}

impl <E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Job for ReceiveJob<E, C, T, B> {
    fn queue(&self) -> &Queue<Self> {
        &self.inner.state.peer.inbound
    }

    fn is_ready(&self) -> bool {
        self.inner.ready.load(Ordering::Acquire)
    }

    fn parallel_work(&self) {
        // TODO: refactor
        // decrypt
        {
            let job = &self.inner;
            let peer = &job.state.peer;
            let mut msg = job.buffer.lock();
            
            let failed = || {
                // cast to header followed by payload
                let (header, packet): (LayoutVerified<&mut [u8], TransportHeader>, &mut [u8]) =
                match LayoutVerified::new_from_prefix(&mut msg.1[..]) {
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
                        UnboundKey::new(&CHACHA20_POLY1305, &job.state.keypair.recv.key[..]).unwrap(),
                    );

                    // attempt to open (and authenticate) the body
                    match key.open_in_place(nonce, Aad::empty(), packet) {
                        Ok(_) => (),
                        Err(_) => {
                            // fault and return early
                            log::trace!("inbound worker: authentication failure");
                            msg.1.truncate(0);
                            return;
                        }
                    }
                }

                // check that counter not after reject
                if header.f_counter.get() >= REJECT_AFTER_MESSAGES {
                    msg.1.truncate(0);
                    return;
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
                        msg.1.truncate(0);
                    }
                    Some(len) => {
                        log::trace!(
                            "inbound worker: good route, length = {} {}",
                            len,
                            if len == 0 { "(keepalive)" } else { "" }
                        );
                        msg.1.truncate(mem::size_of::<TransportHeader>() + len);
                    }
                }
            };
        }

        // mark ready
        self.inner.ready.store(true, Ordering::Release);
    }

    fn sequential_work(self) {
        let job = &self.inner;
        let peer = &job.state.peer;
        let mut msg = job.buffer.lock();

        // cast transport header
        let (header, packet): (LayoutVerified<&[u8], TransportHeader>, &[u8]) =
            match LayoutVerified::new_from_prefix(&msg.1[..]) {
                Some(v) => v,
                None => {
                    // also covers authentication failure
                    return;
                }
            };

        // check for replay
        if !job.state.protector.lock().update(header.f_counter.get()) {
            log::debug!("inbound worker: replay detected");
            return;
        }

        // check for confirms key
        if !job.state.confirmed.swap(true, Ordering::SeqCst) {
            log::debug!("inbound worker: message confirms key");
            peer.confirm_key(&job.state.keypair);
        }

        // update endpoint
        *peer.endpoint.lock() = msg.0.take();

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
        C::recv(&peer.opaque, msg.1.len(), sent, &job.state.keypair);
    }

}
