use super::device::DecryptionState;
use super::ip::inner_length;
use super::messages::TransportHeader;
use super::queue::{ParallelJob, Queue, SequentialJob};
use super::types::Callbacks;
use super::{REJECT_AFTER_MESSAGES, SIZE_TAG};

use super::super::{tun, udp, Endpoint};

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use spin::Mutex;
use zerocopy::{AsBytes, LayoutVerified};

struct Inner<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    ready: AtomicBool,                       // job status
    buffer: Mutex<(Option<E>, Vec<u8>)>,     // endpoint & ciphertext buffer
    state: Arc<DecryptionState<E, C, T, B>>, // decryption state (keys and replay protector)
}

pub struct ReceiveJob<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
    Arc<Inner<E, C, T, B>>,
);

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> Clone
    for ReceiveJob<E, C, T, B>
{
    fn clone(&self) -> ReceiveJob<E, C, T, B> {
        ReceiveJob(self.0.clone())
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> ReceiveJob<E, C, T, B> {
    pub fn new(
        buffer: Vec<u8>,
        state: Arc<DecryptionState<E, C, T, B>>,
        endpoint: E,
    ) -> ReceiveJob<E, C, T, B> {
        ReceiveJob(Arc::new(Inner {
            ready: AtomicBool::new(false),
            buffer: Mutex::new((Some(endpoint), buffer)),
            state,
        }))
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> ParallelJob
    for ReceiveJob<E, C, T, B>
{
    fn queue(&self) -> &Queue<Self> {
        &self.0.state.peer.inbound
    }

    /* The parallel section of an incoming job:
     *
     * - Decryption.
     * - Crypto-key routing lookup.
     *
     * Note: We truncate the message buffer to 0 bytes in case of authentication failure
     * or crypto-key routing failure (attempted impersonation).
     *
     * Note: We cannot do replay protection in the parallel job,
     * since this can cause dropping of packets (leaving the window) due to scheduling.
     */
    fn parallel_work(&self) {
        debug_assert_eq!(
            self.is_ready(),
            false,
            "doing parallel work on completed job"
        );
        log::trace!("processing parallel receive job");

        // decrypt
        {
            // closure for locking
            let job = &self.0;
            let peer = &job.state.peer;
            let mut msg = job.buffer.lock();

            // process buffer
            let ok = (|| {
                // cast to header followed by payload
                let (header, packet): (LayoutVerified<&mut [u8], TransportHeader>, &mut [u8]) =
                    match LayoutVerified::new_from_prefix(&mut msg.1[..]) {
                        Some(v) => v,
                        None => return false,
                    };

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
                    Err(_) => return false,
                }

                // check that counter not after reject
                if header.f_counter.get() >= REJECT_AFTER_MESSAGES {
                    return false;
                }

                // check crypto-key router
                packet.len() == SIZE_TAG || peer.device.table.check_route(&peer, &packet)
            })();

            // remove message in case of failure:
            // to indicate failure and avoid later accidental use of unauthenticated data.
            if !ok {
                msg.1.truncate(0);
            }
        };

        // mark ready
        self.0.ready.store(true, Ordering::Release);
    }
}

impl<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> SequentialJob
    for ReceiveJob<E, C, T, B>
{
    fn is_ready(&self) -> bool {
        self.0.ready.load(Ordering::Acquire)
    }

    fn sequential_work(self) {
        debug_assert_eq!(
            self.is_ready(),
            true,
            "doing sequential work on an incomplete job"
        );
        log::trace!("processing sequential receive job");

        let job = &self.0;
        let peer = &job.state.peer;
        let mut msg = job.buffer.lock();
        let endpoint = msg.0.take();

        // cast transport header
        let (header, packet): (LayoutVerified<&[u8], TransportHeader>, &[u8]) =
            match LayoutVerified::new_from_prefix(&msg.1[..]) {
                Some(v) => v,
                None => {
                    // also covers authentication failure (will fail to parse header)
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
        *peer.endpoint.lock() = endpoint;

        // check if should be written to TUN
        // (keep-alive and malformed packets will have no inner length)
        if let Some(inner) = inner_length(packet) {
            if inner + SIZE_TAG <= packet.len() {
                let _ = peer.device.inbound.write(&packet[..inner]).map_err(|e| {
                    log::debug!("failed to write inbound packet to TUN: {:?}", e);
                });
            }
        }

        // trigger callback
        C::recv(&peer.opaque, msg.1.len(), true, &job.state.keypair);
    }
}
