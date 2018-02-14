use blake2_rfc::blake2s::blake2s;
use failure::{Error, SyncFailure};
use snow::{NoiseBuilder, Session};
use snow::params::NoiseParams;
use subtle;


lazy_static! {
    static ref NOISE_PARAMS: NoiseParams = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

/// Wrapper around the `snow` library to easily setup the handshakes for WireGuard.
pub struct Noise {}
impl Noise {
    fn new_foundation(local_privkey: &[u8]) -> NoiseBuilder {
        NoiseBuilder::new(NOISE_PARAMS.clone())
            .local_private_key(local_privkey)
            .prologue(b"WireGuard v1 zx2c4 Jason@zx2c4.com")
    }

    pub fn build_initiator(local_privkey: &[u8], remote_pubkey: &[u8], psk: &Option<[u8; 32]>) -> Result<Session, Error> {
        Ok(Noise::new_foundation(local_privkey)
            .remote_public_key(remote_pubkey)
            .psk(2, psk.as_ref().unwrap_or_else(|| &[0u8; 32]))
            .build_initiator()
            .map_err(SyncFailure::new)?)
    }

    pub fn build_responder(local_privkey: &[u8]) -> Result<Session, Error> {
        Ok(Noise::new_foundation(local_privkey)
            .build_responder()
            .map_err(SyncFailure::new)?)
    }

    pub fn build_mac1(pub_key: &[u8], mac_input: &[u8], mac_output: &mut [u8]) {
        debug_assert!(mac_output.len() == 16);
        let mut mac_key_input = [0; 40];
        mac_key_input[..8].copy_from_slice(b"mac1----");
        mac_key_input[8..40].copy_from_slice(pub_key);
        let mac_key = blake2s(32, &[], &mac_key_input);
        let mac = blake2s(16, mac_key.as_bytes(), mac_input);
        mac_output.copy_from_slice(mac.as_bytes());
    }

    pub fn verify_mac1(pub_key: &[u8], mac_input: &[u8], mac: &[u8]) -> Result<(), Error> {
        debug_assert!(mac.len() == 16);
        let mut mac_key_input = [0; 40];
        mac_key_input[..8].copy_from_slice(b"mac1----");
        mac_key_input[8..40].copy_from_slice(pub_key);
        let mac_key = blake2s(32, &[], &mac_key_input);
        let our_mac = blake2s(16, mac_key.as_bytes(), mac_input);

        ensure!(subtle::slices_equal(mac, our_mac.as_bytes()) == 1, "mac mismatch");
        Ok(())
    }
}
