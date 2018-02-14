use base64;
use std::io::{Cursor, Read, Write};
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt};
use std::fmt::{self, Display, Formatter};
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Debug, Default)]
pub struct PeerInfo {
    pub pub_key: [u8; 32],
    pub psk: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<(IpAddr, u32)>,
    pub keep_alive_interval: Option<u16>,
}

impl Display for PeerInfo {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let encoded = base64::encode(&self.pub_key);
        write!(f, "{}...{}", &encoded[..4], &encoded[encoded.len()-4..])
    }
}

#[derive(Clone, Debug, Default)]
pub struct InterfaceInfo {
    pub private_key: Option<[u8; 32]>,
    pub pub_key: Option<[u8; 32]>,
    pub listen_port: Option<u16>,
}

pub enum Message {
    HandshakeInitiation(HandshakeInitiationMessage),
//    HandshakeResponse(HandshakeResponseMessage),
//    Transport(TransportMessage),
//    CookieReply(CookieReplyMessage),
    Other(Vec<u8>)
}

// TODO use TryFrom
impl<'a> From<&'a [u8]> for Message {
    fn from(bytes: &'a [u8]) -> Self {
        use self::Message::*;
        let mut cursor = Cursor::new(bytes);
        match cursor.read_u8().unwrap() {
            1 => HandshakeInitiation(HandshakeInitiationMessage::from(&bytes[4..])),
            _ => Other((&bytes[4..]).to_owned())
        }
    }
}

impl From<Message> for Vec<u8> {
    fn from(message: Message) -> Self {
        use self::Message::*;
        match message {
            HandshakeInitiation(message) => {
                let mut bytes = vec![1u8, 0, 0, 0];
                bytes.append(&mut message.into());
                bytes
            },
            _ => unimplemented!()
        }
    }
}

pub struct HandshakeInitiationMessage {
    pub sender_i: u32,
    pub payload: [u8; 76],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16]
}

impl HandshakeInitiationMessage {
    pub fn new() -> Self {
        HandshakeInitiationMessage {
            sender_i: 0,
            payload: [0u8; 76],
            mac1: [0u8; 16],
            mac2: [0u8; 16],
        }
    }
}

impl<'a> From<&'a [u8]> for HandshakeInitiationMessage {

    fn from(bytes: &'a [u8]) -> Self {
        let mut message = HandshakeInitiationMessage::new();
        let mut cursor = Cursor::new(bytes);

        message.sender_i = cursor.read_u32::<LittleEndian>().unwrap();
        cursor.read_exact(&mut message.payload[..]).unwrap();
        cursor.read_exact(&mut message.mac1[..]).unwrap();
        cursor.read_exact(&mut message.mac2[..]).unwrap();
        message
    }
}

impl From<HandshakeInitiationMessage> for Vec<u8> {
    fn from(message: HandshakeInitiationMessage) -> Self {
        let mut cursor = vec![];
        cursor.write_all(&[1u8, 0, 0, 0]).unwrap();
        cursor.write_u32::<LittleEndian>(message.sender_i).unwrap();
        cursor.write_all(&message.payload).unwrap();
        cursor.write_all(&message.mac1).unwrap();
        cursor.write_all(&message.mac2).unwrap();

        cursor
    }
}