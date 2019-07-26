#[cfg(test)]
use hex;

#[cfg(test)]
use std::fmt;

use byteorder::LittleEndian;
use zerocopy::byteorder::U32;
use zerocopy::{AsBytes, ByteSlice, FromBytes, LayoutVerified};

use crate::types::*;

const SIZE_TAG: usize = 16;
const SIZE_X25519_POINT: usize = 32;
const SIZE_TIMESTAMP: usize = 12;

pub const TYPE_INITIATION: u8 = 1;
pub const TYPE_RESPONSE: u8 = 2;

#[repr(C)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct Initiation {
    f_type: U32<LittleEndian>,
    pub f_sender: U32<LittleEndian>,
    pub f_ephemeral: [u8; SIZE_X25519_POINT],
    pub f_static: [u8; SIZE_X25519_POINT],
    pub f_static_tag: [u8; SIZE_TAG],
    pub f_timestamp: [u8; SIZE_TIMESTAMP],
    pub f_timestamp_tag: [u8; SIZE_TAG],
}

impl Default for Initiation {
    fn default() -> Self {
        Self {
            f_type: <U32<LittleEndian>>::new(TYPE_INITIATION as u32),

            f_sender: <U32<LittleEndian>>::ZERO,
            f_ephemeral: [0u8; SIZE_X25519_POINT],
            f_static: [0u8; SIZE_X25519_POINT],
            f_static_tag: [0u8; SIZE_TAG],
            f_timestamp: [0u8; SIZE_TIMESTAMP],
            f_timestamp_tag: [0u8; SIZE_TAG],
        }
    }
}

impl Initiation {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<LayoutVerified<B, Self>, HandshakeError> {
        let msg: LayoutVerified<B, Self> =
            LayoutVerified::new(bytes).ok_or(HandshakeError::InvalidMessageFormat)?;

        if msg.f_type.get() != (TYPE_INITIATION as u32) {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        Ok(msg)
    }
}

#[cfg(test)]
impl fmt::Debug for Initiation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "MessageInitiation {{ type = {}, sender = {}, ephemeral = {}, static = {}|{}, timestamp = {}|{} }}",
            self.f_type.get(),
            self.f_sender.get(),
            hex::encode(self.f_ephemeral),
            hex::encode(self.f_static),
            hex::encode(self.f_static_tag),
            hex::encode(self.f_timestamp),
            hex::encode(self.f_timestamp_tag)
        )
    }
}

#[cfg(test)]
impl PartialEq for Initiation {
    fn eq(&self, other: &Self) -> bool {
        self.f_type.get() == other.f_type.get()
            && self.f_sender.get() == other.f_sender.get()
            && self.f_ephemeral[..] == other.f_ephemeral[..]
            && self.f_static[..] == other.f_static[..]
            && self.f_static_tag[..] == other.f_static_tag[..]
            && self.f_timestamp[..] == other.f_timestamp
            && self.f_timestamp_tag[..] == other.f_timestamp_tag
    }
}

#[cfg(test)]
impl Eq for Initiation {}

#[repr(C)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct Response {
    f_type: U32<LittleEndian>,
    pub f_sender: U32<LittleEndian>,
    pub f_receiver: U32<LittleEndian>,
    pub f_ephemeral: [u8; SIZE_X25519_POINT],
    pub f_empty_tag: [u8; SIZE_TAG],
}

impl Response {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<LayoutVerified<B, Self>, HandshakeError> {
        let msg: LayoutVerified<B, Self> =
            LayoutVerified::new(bytes).ok_or(HandshakeError::InvalidMessageFormat)?;

        if msg.f_type.get() != (TYPE_RESPONSE as u32) {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        Ok(msg)
    }
}

impl Default for Response {
    fn default() -> Self {
        Self {
            f_type: <U32<LittleEndian>>::new(TYPE_RESPONSE as u32),
            f_sender: <U32<LittleEndian>>::ZERO,
            f_receiver: <U32<LittleEndian>>::ZERO,
            f_ephemeral: [0u8; SIZE_X25519_POINT],
            f_empty_tag: [0u8; SIZE_TAG],
        }
    }
}

#[cfg(test)]
impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "MessageResponse {{ type = {}, sender = {}, receiver = {}, ephemeral = {}, empty = |{}  }}",
            self.f_type,
            self.f_sender,
            self.f_receiver,
            hex::encode(self.f_ephemeral),
            hex::encode(self.f_empty_tag)
        )
    }
}

#[cfg(test)]
impl PartialEq for Response {
    fn eq(&self, other: &Self) -> bool {
        self.f_type == other.f_type
            && self.f_sender == other.f_sender
            && self.f_receiver == other.f_receiver
            && self.f_ephemeral == other.f_ephemeral
            && self.f_empty_tag == other.f_empty_tag
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_response_identity() {
        let mut msg: Response = Default::default();

        msg.f_sender.set(146252);
        msg.f_receiver.set(554442);
        msg.f_ephemeral = [
            0xc1, 0x66, 0x0a, 0x0c, 0xdc, 0x0f, 0x6c, 0x51, 0x0f, 0xc2, 0xcc, 0x51, 0x52, 0x0c,
            0xde, 0x1e, 0xf7, 0xf1, 0xca, 0x90, 0x86, 0x72, 0xad, 0x67, 0xea, 0x89, 0x45, 0x44,
            0x13, 0x56, 0x52, 0x1f,
        ];
        msg.f_empty_tag = [
            0x60, 0x0e, 0x1e, 0x95, 0x41, 0x6b, 0x52, 0x05, 0xa2, 0x09, 0xe1, 0xbf, 0x40, 0x05,
            0x2f, 0xde,
        ];

        let buf: Vec<u8> = msg.as_bytes().to_vec();
        let msg_p = Response::parse(&buf[..]).unwrap();
        assert_eq!(msg, *msg_p.into_ref());
    }

    #[test]
    fn message_initiate_identity() {
        let mut msg: Initiation = Default::default();

        msg.f_sender.set(575757);
        msg.f_ephemeral = [
            0xc1, 0x66, 0x0a, 0x0c, 0xdc, 0x0f, 0x6c, 0x51, 0x0f, 0xc2, 0xcc, 0x51, 0x52, 0x0c,
            0xde, 0x1e, 0xf7, 0xf1, 0xca, 0x90, 0x86, 0x72, 0xad, 0x67, 0xea, 0x89, 0x45, 0x44,
            0x13, 0x56, 0x52, 0x1f,
        ];
        msg.f_static = [
            0xdc, 0x33, 0x90, 0x15, 0x8f, 0x82, 0x3e, 0x06, 0x44, 0xa0, 0xde, 0x4c, 0x15, 0x6c,
            0x5d, 0xa4, 0x65, 0x99, 0xf6, 0x6c, 0xa1, 0x14, 0x77, 0xf9, 0xeb, 0x6a, 0xec, 0xc3,
            0x3c, 0xda, 0x47, 0xe1,
        ];
        msg.f_static_tag = [
            0x45, 0xac, 0x8d, 0x43, 0xea, 0x1b, 0x2f, 0x02, 0x45, 0x5d, 0x86, 0x37, 0xee, 0x83,
            0x6b, 0x42,
        ];
        msg.f_timestamp = [
            0x4f, 0x1c, 0x60, 0xec, 0x0e, 0xf6, 0x36, 0xf0, 0x78, 0x28, 0x57, 0x42,
        ];
        msg.f_timestamp_tag = [
            0x60, 0x0e, 0x1e, 0x95, 0x41, 0x6b, 0x52, 0x05, 0xa2, 0x09, 0xe1, 0xbf, 0x40, 0x05,
            0x2f, 0xde,
        ];

        let buf: Vec<u8> = msg.as_bytes().to_vec();
        let msg_p = Initiation::parse(&buf[..]).unwrap();
        assert_eq!(msg, *msg_p.into_ref());
    }
}
