use std::mem;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Weak};

use futures::sync::oneshot;
use futures::*;

use log::debug;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use std::sync::atomic::{AtomicBool, Ordering};
use zerocopy::{AsBytes, LayoutVerified};

use super::device::DecryptionState;
use super::device::DeviceInner;
use super::messages::TransportHeader;
use super::peer::PeerInner;
use super::types::Callbacks;

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
pub type JobInbound<C, T, B> = (Weak<DecryptionState<C, T, B>>, oneshot::Receiver<JobBuffer>);
pub type JobOutbound = oneshot::Receiver<JobBuffer>;

pub fn worker_inbound<C: Callbacks, T: Tun, B: Bind>(
    device: Arc<DeviceInner<C, T, B>>, // related device
    peer: Arc<PeerInner<C, T, B>>,     // related peer
    receiver: Receiver<JobInbound<C, T, B>>,
) {
    loop {
        // fetch job
        let (state, rx) = match receiver.recv() {
            Ok(v) => v,
            _ => {
                return;
            }
        };

        // wait for job to complete
        let _ = rx
            .map(|buf| {
                if buf.okay {
                    // parse / cast
                    let (header, packet) = match LayoutVerified::new_from_prefix(&buf.msg[..]) {
                        Some(v) => v,
                        None => {
                            return;
                        }
                    };
                    let header: LayoutVerified<&[u8], TransportHeader> = header;

                    // obtain strong reference to decryption state
                    let state = if let Some(state) = state.upgrade() {
                        state
                    } else {
                        return;
                    };

                    // check for replay
                    if !state.protector.lock().update(header.f_counter.get()) {
                        return;
                    }

                    // check for confirms key
                    if !state.confirmed.swap(true, Ordering::SeqCst) {
                        peer.confirm_key(state.keypair.clone());
                    }

                    // update endpoint, TODO

                    // write packet to TUN device, TODO

                    // trigger callback
                    debug_assert!(
                        packet.len() >= CHACHA20_POLY1305.nonce_len(),
                        "this should be checked earlier in the pipeline"
                    );
                    (device.call_recv)(
                        &peer.opaque,
                        packet.len() > CHACHA20_POLY1305.nonce_len(),
                        true,
                    );
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
                    // write to UDP device, TODO
                    let xmit = false;

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
        let (header, packet) = match LayoutVerified::new_from_prefix(&buf.msg[..]) {
            Some(v) => v,
            None => continue,
        };

        if packet.len() < CHACHA20_POLY1305.nonce_len() {
            continue;
        }

        let header: LayoutVerified<&[u8], TransportHeader> = header;

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