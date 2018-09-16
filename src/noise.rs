/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

use failure::Error;
use snow::{NoiseBuilder, Session};
use snow::params::NoiseParams;

lazy_static! {
    static ref NOISE_PARAMS: NoiseParams = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

/// Wrapper around the `snow` library to easily setup the handshakes for WireGuard.
fn new_foundation(local_privkey: &[u8]) -> NoiseBuilder {
    NoiseBuilder::new(NOISE_PARAMS.clone())
        .local_private_key(local_privkey)
        .prologue(b"WireGuard v1 zx2c4 Jason@zx2c4.com")
}

pub fn build_initiator(local_privkey: &[u8], remote_pubkey: &[u8], psk: &Option<[u8; 32]>) -> Result<Session, Error> {
    new_foundation(local_privkey)
        .remote_public_key(remote_pubkey)
        .psk(2, psk.as_ref().unwrap_or_else(|| &[0u8; 32]))
        .build_initiator()
}

pub fn build_responder(local_privkey: &[u8]) -> Result<Session, Error> {
    new_foundation(local_privkey)
        .build_responder()
}
