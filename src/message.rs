#![allow(unused)]

use failure::Error;
use std::convert::{TryFrom, TryInto};
use byteorder::{ByteOrder, LittleEndian};

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

#[derive(Deref)]
pub struct Initiation(Vec<u8>);

impl Initiation {
    pub fn their_index(&self) -> u32 {
        LittleEndian::read_u32(&self[4..])
    }

    pub fn noise_bytes(&self) -> &[u8] {
        &self[8..116]
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self
    }
}

impl TryFrom<Vec<u8>> for Initiation {
    type Error = Error;

    fn try_from(packet: Vec<u8>) -> Result<Self, Self::Error> {
        ensure!(packet.len() == 148, "incorrect handshake initiation packet length.");
        Ok(Initiation(packet))
    }
}

#[derive(Deref)]
pub struct Response(Vec<u8>);

impl Response {
    pub fn their_index(&self) -> u32 {
        LittleEndian::read_u32(&self[4..])
    }

    pub fn our_index(&self) -> u32 {
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
        &self
    }
}

impl TryFrom<Vec<u8>> for Response {
    type Error = Error;

    fn try_from(packet: Vec<u8>) -> Result<Self, Self::Error> {
        ensure!(packet.len() == 92, "incorrect handshake response packet length.");
        Ok(Response(packet))
    }
}

#[derive(Deref)]
pub struct CookieReply(Vec<u8>);

impl CookieReply {
    pub fn our_index(&self) -> u32 {
        LittleEndian::read_u32(&self[4..])
    }

    pub fn nonce(&self) -> &[u8] {
        &self[8..32]
    }

    pub fn cookie(&self) -> &[u8] {
        &self[32..48]
    }

    pub fn aead_tag(&self) -> &[u8] {
        &self[48..64]
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self
    }
}

impl TryFrom<Vec<u8>> for CookieReply {
    type Error = Error;

    fn try_from(packet: Vec<u8>) -> Result<Self, Self::Error> {
        ensure!(packet.len() == 64, "incorrect cookie reply packet length.");
        Ok(CookieReply(packet))
    }
}

#[derive(Deref)]
pub struct Transport(Vec<u8>);

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
        &self
    }
}

impl TryFrom<Vec<u8>> for Transport {
    type Error = Error;

    fn try_from(packet: Vec<u8>) -> Result<Self, Self::Error> {
        ensure!(packet.len() >= 32, "transport message smaller than minimum length.");
        Ok(Transport(packet))
    }
}
