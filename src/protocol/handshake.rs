// Copyright 2017 Guanhao Yin <sopium@mysterious.site>

// This file is part of WireGuard.rs.

// WireGuard.rs is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// WireGuard.rs is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with WireGuard.rs.  If not, see <https://www.gnu.org/licenses/>.

extern crate blake2_rfc;
extern crate noise_protocol;
extern crate noise_sodiumoxide;
extern crate sodiumoxide;
extern crate tai64;

use self::blake2_rfc::blake2s::Blake2s;
use self::noise_protocol::*;
use self::noise_protocol::patterns::noise_ik;
use self::noise_sodiumoxide::{ChaCha20Poly1305, X25519};
use self::sodiumoxide::utils::memcmp;
use self::tai64::TAI64N;
use protocol::*;

const PROLOGUE: &'static [u8] = b"WireGuard v0 zx2c4 Jason@zx2c4.com";

pub const HANDSHAKE_INIT_LEN: usize = 148;
pub const HANDSHAKE_RESP_LEN: usize = 92;

pub type HS = HandshakeState<X25519, ChaCha20Poly1305, NoiseBlake2s>;

#[derive(Clone)]
pub struct NoiseBlake2s(Blake2s);

impl Default for NoiseBlake2s {
    fn default() -> Self {
        NoiseBlake2s(Blake2s::new(32))
    }
}

impl Hash for NoiseBlake2s {
    type Output = [u8; 32];
    type Block = [u8; 64];

    fn name() -> &'static str {
        "BLAKE2s"
    }

    fn input(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn result(&mut self) -> Self::Output {
        Self::Output::from_slice(self.0
            .clone()
            .finalize()
            .as_bytes())
    }
}

/// Calc mac/hash of some data, with an optional key.
///
/// This is exactly the mac function defined in WireGuard paper.
fn mac<K>(key: Option<K>, data: &[&[u8]]) -> [u8; 16]
    where K: AsRef<[u8]>
{
    let mut mac = [0u8; 16];
    let mut blake2s = Blake2s::with_key(16, key.as_ref().map_or(&[], |k| k.as_ref()));
    for d in data {
        blake2s.update(d);
    }
    mac.copy_from_slice(blake2s.finalize().as_bytes());
    mac
}

/// Generate handshake initiation message.
///
/// Will generate a new ephemeral key and use current timestamp.
///
/// Returns: Message, noise handshake state.
pub fn initiate(wg: &WgInfo, peer: &PeerInfo, self_index: Id) -> ([u8; HANDSHAKE_INIT_LEN], HS) {
    let mut msg = [0u8; HANDSHAKE_INIT_LEN];

    let mut hs = {
        let mut hsbuilder = HandshakeStateBuilder::<X25519>::new();
        hsbuilder.set_pattern(noise_ik());
        hsbuilder.set_is_initiator(true);
        hsbuilder.set_prologue(PROLOGUE);
        if let Some(ref psk) = wg.psk {
            hsbuilder.set_psk(psk.as_slice());
        }
        hsbuilder.set_s(wg.key.clone());
        hsbuilder.set_rs(peer.peer_pubkey);
        hsbuilder.build_handshake_state()
    };

    // Type and reserved zeros.
    msg[0..4].copy_from_slice(&[1, 0, 0, 0]);
    // Self index.
    msg[4..8].copy_from_slice(self_index.as_slice());

    // Noise part: e, s, timestamp.
    let timestamp = TAI64N::now();
    hs.write_message(&timestamp.to_external(), &mut msg[8..116]);

    // Mac1.
    let mac1 = mac(wg.psk.as_ref(),
                   &[peer.peer_pubkey.as_slice(), &msg[..116]]);
    msg[116..132].copy_from_slice(&mac1);

    (msg, hs)
}

pub struct InitProcessResult {
    pub peer_id: Id,
    pub timestamp: TAI64N,
    pub handshake_state: HS,
}

/// Process a handshake initiation message.
///
/// Will generate a new ephemeral key.
///
/// # Panics
///
/// If the message length is not `HANDSHAKE_INIT_LEN`.
pub fn process_initiation(wg: &WgInfo, msg: &[u8]) -> Result<InitProcessResult, ()> {
    debug_assert_eq!(msg.len(), HANDSHAKE_INIT_LEN);

    // Check mac1.
    let mac1 = mac(wg.psk.as_ref(), &[&wg.pubkey, &msg[..116]]);
    if !memcmp(&mac1, &msg[116..132]) {
        return Err(());
    }

    // Check type and zeros.
    if &msg[0..4] != &[1, 0, 0, 0] {
        return Err(());
    }

    // Peer index.
    let peer_index = Id::from_slice(&msg[4..8]);

    let mut hs: HS = {
        let mut hsbuilder = HandshakeStateBuilder::<X25519>::new();
        hsbuilder.set_is_initiator(false);
        hsbuilder.set_prologue(PROLOGUE);
        hsbuilder.set_pattern(noise_ik());
        if let Some(ref psk) = wg.psk {
            hsbuilder.set_psk(psk);
        }
        hsbuilder.set_s(wg.key.clone());
        hsbuilder.build_handshake_state()
    };

    // Noise message, contains encrypted timestamp.
    let mut timestamp = [0u8; 12];
    hs.read_message(&msg[8..116], &mut timestamp).map_err(|_| ())?;
    let timestamp = TAI64N::from_external(&timestamp).ok_or(())?;

    Ok(InitProcessResult {
        peer_id: peer_index,
        timestamp: timestamp,
        handshake_state: hs,
    })
}

/// Generate handshake response message.
pub fn responde(wg: &WgInfo, result: &mut InitProcessResult, self_id: Id)
        -> [u8; HANDSHAKE_RESP_LEN] {
    let mut response = [0u8; HANDSHAKE_RESP_LEN];

    // Type and zeros.
    response[0..4].copy_from_slice(&[2, 0, 0, 0]);
    response[4..8].copy_from_slice(self_id.as_slice());
    response[8..12].copy_from_slice(result.peer_id.as_slice());

    let mut hs = &mut result.handshake_state;

    hs.write_message(&[], &mut response[12..60]);

    let mac1 = mac(wg.psk.as_ref(), &[hs.get_rs().as_ref().unwrap(), &response[..60]]);
    response[60..76].copy_from_slice(&mac1);

    response
}

/// Process handshake response message.
///
/// Returns peer index.
///
/// # Panics
///
/// If the message length is not `HANDSHAKE_RESP_LEN`.
pub fn process_response(wg: &WgInfo, hs: &mut HS, msg: &[u8]) -> Result<Id, ()> {
    debug_assert_eq!(msg.len(), HANDSHAKE_RESP_LEN);

    // Check mac1.
    let mac1 = mac(wg.psk.as_ref(), &[&wg.pubkey, &msg[..60]]);

    if !memcmp(&mac1, &msg[60..76]) {
        return Err(());
    }

    // Check type and zeros.
    if &msg[0..4] != &[2, 0, 0, 0] {
        return Err(());
    }

    // Peer index.
    let peer_index = Id::from_slice(&msg[4..8]);

    // msg[8..12] is self index, skip.

    let mut out = [];

    hs.read_message(&msg[12..60], &mut out).map_err(|_| ())?;

    Ok(peer_index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wg_handshake_init_responde() {
        let k = X25519::genkey();
        let init = WgInfo {
            psk: None,
            pubkey: X25519::pubkey(&k),
            key: k,
        };

        let k = X25519::genkey();
        let resp = WgInfo {
            psk: None,
            pubkey: X25519::pubkey(&k),
            key: k,
        };

        let init_peer = PeerInfo {
            peer_pubkey: Clone::clone(&resp.pubkey),
            endpoint: None,
            allowed_ips: vec![],
            keep_alive_interval: None,
        };

        let si = Id::gen();
        let (m0, mut ihs) = initiate(&init, &init_peer, si);
        let mut result0 = process_initiation(&resp, &m0).unwrap();
        let ri = Id::gen();
        let m1 = responde(&resp, &mut result0, ri);
        let ri1 = process_response(&init, &mut ihs, &m1).unwrap();

        assert_eq!(result0.peer_id, si);
        assert_eq!(ri1, ri);

        assert_eq!(ihs.get_hash(), result0.handshake_state.get_hash());
    }

    #[test]
    fn wg_handshake_init_responde_with_psk() {
        let psk = [0xc7; 32];

        let k = X25519::genkey();
        let init = WgInfo {
            psk: Some(psk),
            pubkey: X25519::pubkey(&k),
            key: k,
        };

        let k = X25519::genkey();
        let resp = WgInfo {
            psk: Some(psk),
            pubkey: X25519::pubkey(&k),
            key: k,
        };

        let init_peer = PeerInfo {
            peer_pubkey: Clone::clone(&resp.pubkey),
            endpoint: None,
            allowed_ips: vec![],
            keep_alive_interval: None,
        };

        let si = Id::gen();
        let (m0, mut ihs) = initiate(&init, &init_peer, si);
        let mut result0 = process_initiation(&resp, &m0).unwrap();
        let ri = Id::gen();
        let m1 = responde(&resp, &mut result0, ri);
        let ri1 = process_response(&init, &mut ihs, &m1).unwrap();

        assert_eq!(result0.peer_id, si);
        assert_eq!(ri1, ri);

        assert_eq!(ihs.get_hash(), result0.handshake_state.get_hash());
    }
}
