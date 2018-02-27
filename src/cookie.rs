#![allow(unused)]

use blake2_rfc::blake2s::{blake2s, Blake2sResult};
use xchacha20poly1305;
use consts::COOKIE_REFRESH_TIME;
use failure::{Error, err_msg};
use rand::{self, Rng};
use subtle;
use std::time::Instant;

pub struct ValidatorMac2 {
    secret: [u8; 16],
    secret_time: Option<Instant>,
    key: Blake2sResult,
}

pub struct GeneratorMac2 {
    cookie: [u8; 16],
    cookie_time: Option<Instant>,
    last_mac1: Option<Blake2sResult>,
    key: Blake2sResult,
}

pub struct Validator {
    mac1_key: Blake2sResult,
    mac2: ValidatorMac2
}

pub struct Generator {
    mac1_key: Blake2sResult,
    mac2: GeneratorMac2,
}

impl Validator {
    pub fn new(pub_key: &[u8]) -> Self {
        let     mac1_key = blake2s(32, &[], &[b"mac1----", pub_key].concat());
        let     mac2_key = blake2s(32, &[], &[b"cookie--", pub_key].concat());

        Self {
            mac1_key,
            mac2: ValidatorMac2 {
                secret: [0u8; 16],
                secret_time: None,
                key: mac2_key,
            }
        }
    }

    pub fn verify_mac1(&self, mac_input: &[u8], mac: &[u8]) -> Result<(), Error> {
        debug_assert!(mac.len() == 16);
        let our_mac = blake2s(16, self.mac1_key.as_bytes(), mac_input);

        ensure!(subtle::slices_equal(mac, our_mac.as_bytes()) == 1, "mac mismatch");
        Ok(())
    }

    pub fn verify_mac2(&self, message: &[u8], source: &[u8]) -> Result<(), Error> {
        let secret_time = self.mac2.secret_time.ok_or_else(|| err_msg("no mac2 secret time set"))?;
        ensure!(Instant::now().duration_since(secret_time) > *COOKIE_REFRESH_TIME, "secret is too old");

        let cookie = blake2s(16, &self.mac2.secret, source);
        let mac2   = blake2s(16, cookie.as_bytes(), &message[..message.len()-16]);

        ensure!(subtle::slices_equal(mac2.as_bytes(), &message[..message.len()-16]) == 1, "mac mismatch");
        Ok(())
    }

    pub fn generate_reply(&mut self, mac1: &[u8], source: &[u8]) -> Result<([u8; 24], [u8; 32]), Error> {
        let mut nonce  = [0u8; 24];
        let mut cookie = [0u8; 32];

        if !is_secret_valid(self.mac2.secret_time) {
            rand::thread_rng().fill_bytes(&mut self.mac2.secret);
            self.mac2.secret_time = Some(Instant::now());
        }

        let input = blake2s(16, &self.mac2.secret, source);
        xchacha20poly1305::encrypt(self.mac2.key.as_bytes(), &nonce, input.as_bytes(), mac1, &mut cookie);

        Ok((nonce, cookie))
    }
}

impl Generator {
    pub fn new(pub_key: &[u8]) -> Self {
        let     mac1_key = blake2s(32, &[], &[b"mac1----", pub_key].concat());
        let     mac2_key = blake2s(32, &[], &[b"cookie--", pub_key].concat());

        Self {
            mac1_key,
            mac2: GeneratorMac2 {
                cookie: [0u8; 16],
                cookie_time: None,
                last_mac1: None,
                key: mac2_key,
            }
        }
    }

    pub fn consume_reply(&mut self, reply: &[u8]) -> Result<(), Error> {
        let last_mac1 = self.mac2.last_mac1.ok_or_else(|| err_msg("no last mac1"))?;

        xchacha20poly1305::decrypt(self.mac2.key.as_bytes(),
                                   &reply[8..32],
                                   &reply[32..48],
                                   last_mac1.as_bytes(),
                                   &reply[48..],
                                   &mut self.mac2.cookie)?;

        self.mac2.cookie_time = Some(Instant::now());
        Ok(())
    }

    pub fn build_macs(&mut self, input: &[u8]) -> (Blake2sResult, Option<Blake2sResult>) {
        let mac1 = blake2s(16, self.mac1_key.as_bytes(), input);

        let mac2 = if is_secret_valid(self.mac2.cookie_time) {
            Some(blake2s(16, &self.mac2.cookie, &[input, mac1.as_bytes()].concat()))
        } else {
            None
        };

        self.mac2.last_mac1 = Some(mac1);
        (mac1, mac2)
    }
}

fn is_secret_valid(secret_time: Option<Instant>) -> bool {
    if let Some(time) = secret_time {
        Instant::now().duration_since(time) <= *COOKIE_REFRESH_TIME
    } else {
        false
    }
}

#[test]
fn sanity() {

}
