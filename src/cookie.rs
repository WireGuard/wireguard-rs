use blake2_rfc::blake2s::blake2s;
use chacha20_poly1305_aead;
use failure::Error;
use subtle;

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
