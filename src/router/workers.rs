use std::iter;
use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, TryRecvError};
use std::sync::{Arc, Weak};
use std::thread;

use spin;

use crossbeam_deque::{Injector, Steal, Stealer, Worker};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use zerocopy::{AsBytes, ByteSlice, ByteSliceMut, FromBytes, LayoutVerified, Unaligned};

use super::device::DecryptionState;
use super::device::DeviceInner;
use super::messages::TransportHeader;
use super::peer::PeerInner;
use super::types::{Callback, KeyCallback, Opaque};

#[derive(PartialEq, Debug)]
pub enum Operation {
    Encryption,
    Decryption,
}

#[derive(PartialEq, Debug)]
enum Status {
    Fault,   // unsealing failed
    Done,    // job valid and complete
    Waiting, // job awaiting completion
}

pub struct JobInner {
    msg: Vec<u8>,   // message buffer (nonce and receiver id set)
    key: [u8; 32],  // chacha20poly1305 key
    status: Status, // state of the job
    op: Operation,  // should be buffer be encrypted / decrypted?
}

pub type JobBuffer = Arc<spin::Mutex<JobInner>>;
pub type JobParallel = (Arc<thread::JoinHandle<()>>, JobBuffer);
pub type JobInbound<T, S, R, K> = (Weak<DecryptionState<T, S, R, K>>, JobBuffer);
pub type JobOutbound = JobBuffer;

/* Strategy for workers acquiring a new job:
 *
 * 1. Try the local job queue (owned by the thread)
 * 2. Try fetching a batch of jobs from the global injector
 * 3. Attempt to steal jobs from other threads.
 */
fn find_task<T>(local: &Worker<T>, global: &Injector<T>, stealers: &[Stealer<T>]) -> Option<T> {
    local.pop().or_else(|| {
        iter::repeat_with(|| {
            global
                .steal_batch_and_pop(local)
                .or_else(|| stealers.iter().map(|s| s.steal()).collect())
        })
        .find(|s| !s.is_retry())
        .and_then(|s| s.success())
    })
}

fn wait_buffer(running: AtomicBool, buf: &JobBuffer) {
    while running.load(Ordering::Acquire) {
        match buf.try_lock() {
            None => (),
            Some(buf) => {
                if buf.status == Status::Waiting {
                    return;
                }
            }
        };
        thread::park();
    }
}

fn wait_recv<T>(running: &AtomicBool, recv: &Receiver<T>) -> Result<T, TryRecvError> {
    while running.load(Ordering::Acquire) {
        match recv.try_recv() {
            Err(TryRecvError::Empty) => (),
            value => {
                return value;
            }
        };
        thread::park();
    }
    return Err(TryRecvError::Disconnected);
}

pub fn worker_inbound<T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>>(
    device: Arc<DeviceInner<T, S, R, K>>,   // related device
    peer: Arc<PeerInner<T, S, R, K>>,       // related peer
    recv: Receiver<JobInbound<T, S, R, K>>, // in order queue
) {
    loop {
        match wait_recv(&peer.stopped, &recv) {
            Ok((state, buf)) => {
                while !peer.stopped.load(Ordering::Acquire) {
                    match buf.try_lock() {
                        None => (),
                        Some(buf) => match buf.status {
                            Status::Done => {
                                // parse / cast
                                let (header, packet) =
                                    match LayoutVerified::new_from_prefix(&buf.msg[..]) {
                                        Some(v) => v,
                                        None => continue,
                                    };
                                let header: LayoutVerified<&[u8], TransportHeader> = header;

                                // obtain strong reference to decryption state
                                let state = if let Some(state) = state.upgrade() {
                                    state
                                } else {
                                    break;
                                };

                                // check for replay
                                if !state.protector.lock().update(header.f_counter.get()) {
                                    break;
                                }

                                // check for confirms key
                                if !state.confirmed.swap(true, Ordering::SeqCst) {
                                    peer.confirm_key(state.keypair.clone());
                                }

                                // update enpoint, TODO

                                // write packet to TUN device, TODO

                                // trigger callback
                                debug_assert!(
                                    packet.len() >= CHACHA20_POLY1305.nonce_len(),
                                    "this should be checked earlier in the pipeline"
                                );
                                (device.event_recv)(
                                    &peer.opaque,
                                    packet.len() > CHACHA20_POLY1305.nonce_len(),
                                    true,
                                );
                                break;
                            }
                            Status::Fault => break,
                            _ => (),
                        },
                    };
                    thread::park();
                }
            }
            Err(_) => {
                break;
            }
        }
    }
}

pub fn worker_outbound<T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>>(
    device: Arc<DeviceInner<T, S, R, K>>, // related device
    peer: Arc<PeerInner<T, S, R, K>>,     // related peer
    recv: Receiver<JobOutbound>,          // in order queue
) {
    loop {
        match wait_recv(&peer.stopped, &recv) {
            Ok(buf) => {
                while !peer.stopped.load(Ordering::Acquire) {
                    match buf.try_lock() {
                        None => (),
                        Some(buf) => match buf.status {
                            Status::Done => {
                                // parse / cast
                                let (header, packet) =
                                    match LayoutVerified::new_from_prefix(&buf.msg[..]) {
                                        Some(v) => v,
                                        None => continue,
                                    };
                                let header: LayoutVerified<&[u8], TransportHeader> = header;

                                // write to UDP device, TODO
                                let xmit = false;

                                // trigger callback
                                (device.event_send)(
                                    &peer.opaque,
                                    buf.msg.len()
                                        > CHACHA20_POLY1305.nonce_len()
                                            + mem::size_of::<TransportHeader>(),
                                    xmit,
                                );
                                break;
                            }
                            Status::Fault => break,
                            _ => (),
                        },
                    };
                    thread::park();
                }
            }
            Err(_) => {
                break;
            }
        }
    }
}

pub fn worker_parallel<T: Opaque, S: Callback<T>, R: Callback<T>, K: KeyCallback<T>>(
    device: Arc<DeviceInner<T, S, R, K>>,
    local: Worker<JobParallel>, // local job queue (local to thread)
    stealers: Vec<Stealer<JobParallel>>, // stealers (from other threads)
) {
    while device.running.load(Ordering::SeqCst) {
        match find_task(&local, &device.injector, &stealers) {
            Some(job) => {
                let (handle, buf) = job;

                // take ownership of the job buffer and complete it
                {
                    let mut buf = buf.lock();

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
                    let key = LessSafeKey::new(
                        UnboundKey::new(&CHACHA20_POLY1305, &buf.key[..]).unwrap(),
                    );

                    // create a nonce object
                    let mut nonce = [0u8; 12];
                    debug_assert_eq!(nonce.len(), CHACHA20_POLY1305.nonce_len()); // why the this is not a constant, god knows...
                    nonce[4..].copy_from_slice(header.f_counter.as_bytes());
                    let nonce = Nonce::assume_unique_for_key(nonce);

                    match buf.op {
                        Operation::Encryption => {
                            // note: extends the vector to accommodate the tag
                            key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf.msg)
                                .unwrap();
                            buf.status = Status::Done;
                        }
                        Operation::Decryption => {
                            // opening failure is signaled by fault state
                            buf.status = match key.open_in_place(nonce, Aad::empty(), &mut buf.msg)
                            {
                                Ok(_) => Status::Done,
                                Err(_) => Status::Fault,
                            };
                        }
                    }
                }

                // ensure consumer is unparked
                handle.thread().unpark();
            }
            None => {
                device.parked.store(true, Ordering::Release);
                thread::park();
            }
        }
    }
}
