#![allow(unused)]

use failure::Error;
use std::convert::{TryFrom, TryInto};
use byteorder::{ByteOrder, LittleEndian};

#[derive(Deref, DerefMut)] pub struct Initiation(Vec<u8>);
#[derive(Deref, DerefMut)] pub struct Response(Vec<u8>);
#[derive(Deref, DerefMut)] pub struct CookieReply(Vec<u8>);
#[derive(Deref, DerefMut)] pub struct Transport(Vec<u8>);

pub enum Message {
    Initiation(Initiation),
    Response(Response),
    CookieReply(CookieReply),
    Transport(Transport),
}

impl TryFrom<Vec<u8>> for Message {
    type Error = Error;

    fn try_from(packet: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(match packet[0] {
            1 => Message::Initiation(packet.try_into()?),
            2 => Message::Response(packet.try_into()?),
            3 => Message::CookieReply(packet.try_into()?),
            4 => Message::Transport(packet.try_into()?),
            _ => bail!("unknown wireguard message type")
        })
    }
}

impl Initiation {
    pub fn sender_index(&self) -> u32 {
        LittleEndian::read_u32(&self[4..])
    }

    pub fn noise_bytes(&self) -> &[u8] {
        &self[8..116]
    }

    pub fn mac1(&self) -> &[u8] {
        &self[84..100]
    }

    pub fn as_bytes(&self) -> &[u8] {
        self
    }
}

impl TryFrom<Vec<u8>> for Initiation {
    type Error = Error;

    fn try_from(packet: Vec<u8>) -> Result<Self, Self::Error> {
        ensure!(packet.len() == 148, "incorrect handshake initiation packet length.");
        Ok(Initiation(packet))
    }
}

impl Response {
    pub fn sender_index(&self) -> u32 {
        LittleEndian::read_u32(&self[4..])
    }

    pub fn receiver_index(&self) -> u32 {
        LittleEndian::read_u32(&self[8..])
    }

    pub fn noise_bytes(&self) -> &[u8] {
        &self[12..60]
    }

    pub fn mac1(&self) -> &[u8] {
        &self[60..76]
    }

    pub fn mac2(&self) -> &[u8] {
        &self[76..92]
    }

    pub fn as_bytes(&self) -> &[u8] {
        self
    }
}

impl TryFrom<Vec<u8>> for Response {
    type Error = Error;

    fn try_from(packet: Vec<u8>) -> Result<Self, Self::Error> {
        ensure!(packet.len() == 92, "incorrect handshake response packet length.");
        Ok(Response(packet))
    }
}

impl CookieReply {
    pub fn new() -> Self {
        let mut buffer = vec![0u8; 64];
        buffer[0] = 3;
        CookieReply(buffer)
    }

    pub fn receiver_index(&self) -> u32 {
        LittleEndian::read_u32(&self[4..8])
    }

    pub fn set_receiver_index(&mut self, index: u32) {
        LittleEndian::write_u32(&mut self[4..8], index)
    }

    pub fn nonce(&self) -> &[u8] {
        &self[8..32]
    }

    pub fn nonce_mut(&mut self) -> &mut [u8] {
        &mut self[8..32]
    }

    pub fn cookie(&self) -> &[u8] {
        &self[32..48]
    }

    pub fn nonce_cookie_mut(&mut self) -> (&mut [u8], &mut [u8]) {
        let (first, second) = self.split_at_mut(32);
        (&mut first[8..32], second)
    }

    pub fn aead_tag(&self) -> &[u8] {
        &self[48..64]
    }

    pub fn as_bytes(&self) -> &[u8] {
        self
    }
}

impl TryFrom<Vec<u8>> for CookieReply {
    type Error = Error;

    fn try_from(packet: Vec<u8>) -> Result<Self, Self::Error> {
        ensure!(packet.len() == 64, "incorrect cookie reply packet length.");
        Ok(CookieReply(packet))
    }
}

impl Transport {
    pub fn our_index(&self) -> u32 {
        LittleEndian::read_u32(&self[4..])
    }

    pub fn nonce(&self) -> u64 {
        LittleEndian::read_u64(&self[8..16])
    }

    pub fn payload(&self) -> &[u8] {
        &self[16..]
    }

    pub fn as_bytes(&self) -> &[u8] {
        self
    }
}

impl TryFrom<Vec<u8>> for Transport {
    type Error = Error;

    fn try_from(packet: Vec<u8>) -> Result<Self, Self::Error> {
        ensure!(packet.len() >= 32, "transport message smaller than minimum length.");
        Ok(Transport(packet))
    }
}
