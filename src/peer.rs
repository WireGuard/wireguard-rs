use std::sync::Mutex;

use generic_array::typenum::U32;
use generic_array::GenericArray;

use x25519_dalek::PublicKey;
use x25519_dalek::SharedSecret;

use crate::types::*;
use crate::timestamp;

/* Represents the recomputation and state of a peer.
 *
 * This type is only for internal use and not exposed.
 */

pub struct Peer {
    pub idx   : usize,

    // mutable state
    state     : Mutex<State>,
    timestamp : Mutex<Option<timestamp::TAI64N>>,

    // constant state
    pub pk  : PublicKey,     // public key of peer
    pub ss  : SharedSecret,  // precomputed DH(static, static)
    pub psk : Psk            // psk of peer
}

#[derive(Debug, Copy, Clone)]
pub enum State {
    Reset,
    InitiationSent{
        hs : GenericArray<u8, U32>,
        ck : GenericArray<u8, U32>
    },
}

impl Peer {
    pub fn new(
        idx : usize,
        pk  : PublicKey,    // public key of peer
        ss  : SharedSecret  // precomputed DH(static, static)
    ) -> Self {
        Self {
            idx       : idx,
            state     : Mutex::new(State::Reset),
            timestamp : Mutex::new(None),
            pk        : pk,
            ss        : ss,
            psk       : [0u8; 32]
        }
    }

    /// Return the state of the peer
    ///
    /// # Arguments
    pub fn get_state(&self) -> State {
        *self.state.lock().unwrap()
    }

    /// Set the state of the peer unconditionally
    ///
    /// # Arguments
    ///
    pub fn set_state(
        &self,
        state_new : State
    ) {
        let mut state = self.state.lock().unwrap();
        *state = state_new;
    }

    /// # Arguments
    ///
    /// * ts_new - The timestamp
    ///
    /// # Returns
    ///
    /// A Boolean indicating if the state was updated
    pub fn check_timestamp(&self,
                           timestamp_new : &timestamp::TAI64N) -> Result<(), HandshakeError> {

        let mut timestamp = self.timestamp.lock().unwrap();
        match *timestamp {
            None => Ok(()),
            Some(timestamp_old) => if timestamp::compare(&timestamp_old, &timestamp_new) {
                *timestamp = Some(*timestamp_new);
                Ok(())
            } else {
                Err(HandshakeError::OldTimestamp)
            }
        }
    }

    /// Set the mutable state of the peer conditioned on the timestamp being newer
    ///
    /// # Arguments
    ///
    /// * st_new - The updated state of the peer
    /// * ts_new - The associated timestamp
    ///
    /// # Returns
    ///
    /// A Boolean indicating if the state was updated
    pub fn set_state_timestamp(
        &self,
        state_new : State,
        timestamp_new : &timestamp::TAI64N
    ) -> Result<(), HandshakeError> {
        let mut state = self.state.lock().unwrap();
        let mut timestamp = self.timestamp.lock().unwrap();
        match *timestamp {
            None => {
                // no prior timestamp know
                *state = state_new;
                *timestamp = Some(*timestamp_new);
                Ok(())
            },
            Some(timestamp_old) => if timestamp::compare(&timestamp_old, &timestamp_new) {
                // new timestamp is strictly greater
                *state = state_new;
                *timestamp = Some(*timestamp_new);
                Ok(())
            } else {
                Err(HandshakeError::OldTimestamp)
            }
        }
    }
}
