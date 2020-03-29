use spin::Mutex;

use std::mem;
use std::time::{Duration, Instant};

use generic_array::typenum::U32;
use generic_array::GenericArray;

use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

use clear_on_drop::clear::Clear;

use super::device::Device;
use super::macs;
use super::timestamp;
use super::types::*;

const TIME_BETWEEN_INITIATIONS: Duration = Duration::from_millis(20);

// Represents the state of a peer.
//
// This type is only for internal use and not exposed.
pub(super) struct Peer<O> {
    // opaque type which identifies a peer
    pub opaque: O,

    // mutable state
    pub state: Mutex<State>,
    pub timestamp: Mutex<Option<timestamp::TAI64N>>,
    pub last_initiation_consumption: Mutex<Option<Instant>>,

    // state related to DoS mitigation fields
    pub macs: Mutex<macs::Generator>,

    // constant state
    pub ss: [u8; 32], // precomputed DH(static, static)
    pub psk: Psk,     // psk of peer
}

pub enum State {
    Reset,
    InitiationSent {
        local: u32, // local id assigned
        eph_sk: StaticSecret,
        hs: GenericArray<u8, U32>,
        ck: GenericArray<u8, U32>,
    },
}

impl Drop for State {
    fn drop(&mut self) {
        match self {
            State::InitiationSent { hs, ck, .. } => {
                // eph_sk already cleared by dalek-x25519
                hs.clear();
                ck.clear();
            }
            _ => (),
        }
    }
}

impl<O> Peer<O> {
    pub fn new(pk: PublicKey, ss: [u8; 32], opaque: O) -> Self {
        Self {
            opaque,
            macs: Mutex::new(macs::Generator::new(pk)),
            state: Mutex::new(State::Reset),
            timestamp: Mutex::new(None),
            last_initiation_consumption: Mutex::new(None),
            ss,
            psk: [0u8; 32],
        }
    }

    pub fn reset_state(&self) -> Option<u32> {
        match mem::replace(&mut *self.state.lock(), State::Reset) {
            State::InitiationSent { local, .. } => Some(local),
            _ => None,
        }
    }

    /// Set the mutable state of the peer conditioned on the timestamp being newer
    ///
    /// # Arguments
    ///
    /// * st_new - The updated state of the peer
    /// * ts_new - The associated timestamp
    pub fn check_replay_flood(
        &self,
        device: &Device<O>,
        timestamp_new: &timestamp::TAI64N,
    ) -> Result<(), HandshakeError> {
        let mut state = self.state.lock();
        let mut timestamp = self.timestamp.lock();
        let mut last_initiation_consumption = self.last_initiation_consumption.lock();

        // check replay attack
        match *timestamp {
            Some(timestamp_old) => {
                if !timestamp::compare(&timestamp_old, &timestamp_new) {
                    return Err(HandshakeError::OldTimestamp);
                }
            }
            _ => (),
        };

        // check flood attack
        match *last_initiation_consumption {
            Some(last) => {
                if last.elapsed() < TIME_BETWEEN_INITIATIONS {
                    return Err(HandshakeError::InitiationFlood);
                }
            }
            _ => (),
        }

        // reset state
        match *state {
            State::InitiationSent { local, .. } => device.release(local),
            _ => (),
        }

        // update replay & flood protection
        *state = State::Reset;
        *timestamp = Some(*timestamp_new);
        *last_initiation_consumption = Some(Instant::now());
        Ok(())
    }
}
