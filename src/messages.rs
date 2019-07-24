use hex;
use std::mem;
use std::fmt;
use std::convert::TryFrom;
use crate::types::*;

const SIZE_TAG : usize = 16;
const SIZE_X25519_POINT : usize = 32;
const SIZE_TIMESTAMP : usize = 12;

pub const TYPE_INITIATION : u8 = 1;
pub const TYPE_RESPONSE : u8 = 2;

/* Functions related to the packing / unpacking of
 * the fixed-sized noise handshake messages.
 *
 * The unpacked types are unexposed implementation details.
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Initiation {
    f_type               : u32,
    pub f_sender         : u32,
    pub f_ephemeral      : [u8; SIZE_X25519_POINT],
    pub f_static         : [u8; SIZE_X25519_POINT],
    pub f_static_tag     : [u8; SIZE_TAG],
    pub f_timestamp      : [u8; SIZE_TIMESTAMP],
    pub f_timestamp_tag  : [u8; SIZE_TAG],
}

impl TryFrom<&[u8]> for Initiation {

    type Error = HandshakeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {

        // check length of slice matches message

        if value.len() != mem::size_of::<Self>() {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        // create owned copy

        let mut owned = [0u8; mem::size_of::<Self>()];
        let mut msg : Self;
        owned.copy_from_slice(value);

        // cast to Initiation

        unsafe {
            msg = mem::transmute::<[u8; mem::size_of::<Self>()], Self>(owned);
        };

        // correct endianness

        msg.f_type = msg.f_type.to_le();
        msg.f_sender = msg.f_sender.to_le();

        // check type and reserved fields

        if msg.f_type != (TYPE_INITIATION as u32) {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        Ok(msg)
    }
}

impl Into<Vec<u8>> for Initiation {
    fn into(self) -> Vec<u8> {
        // correct endianness
        let mut msg = self;
        msg.f_type = msg.f_type.to_le();
        msg.f_sender = msg.f_sender.to_le();

        // cast to array
        let array : [u8; mem::size_of::<Self>()];
        unsafe {
            array = mem::transmute::<Self, [u8; mem::size_of::<Self>()]>(msg)
        };

        array.to_vec()
    }
}

impl Default for Initiation {
    fn default() -> Self {
        Self {
            f_type          : TYPE_INITIATION as u32,
            f_sender        : 0,
            f_ephemeral     : [0u8; SIZE_X25519_POINT],
            f_static        : [0u8; SIZE_X25519_POINT],
            f_static_tag    : [0u8; SIZE_TAG],
            f_timestamp     : [0u8; SIZE_TIMESTAMP],
            f_timestamp_tag : [0u8; SIZE_TAG]
        }
    }
}

impl fmt::Debug for Initiation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "MessageInitiation {{ type = {}, sender = {}, ephemeral = {}, static = {}|{}, timestamp = {}|{} }}",
            self.f_type,
            self.f_sender,
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
        self.f_type == other.f_type &&
        self.f_sender == other.f_sender &&
        self.f_ephemeral[..] == other.f_ephemeral[..] &&
        self.f_static[..] == other.f_static[..] &&
        self.f_static_tag[..] == other.f_static_tag[..] &&
        self.f_timestamp[..] == other.f_timestamp &&
        self.f_timestamp_tag[..] == other.f_timestamp_tag
    }
}

#[cfg(test)]
impl Eq for Initiation {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Response {
    f_type          : u32,
    pub f_sender    : u32,
    pub f_receiver  : u32,
    pub f_ephemeral : [u8; SIZE_X25519_POINT],
    pub f_empty_tag : [u8; SIZE_TAG],
}

impl TryFrom<&[u8]> for Response {

    type Error = HandshakeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {

        // check length of slice matches message

        if value.len() != mem::size_of::<Self>() {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        // create owned copy

        let mut owned = [0u8; mem::size_of::<Self>()];
        let mut msg : Self;
        owned.copy_from_slice(value);

        // cast to MessageResponse

        unsafe {
            msg = mem::transmute::<[u8; mem::size_of::<Self>()], Self>(owned);
        };

        // correct endianness

        msg.f_type = msg.f_type.to_le();
        msg.f_sender = msg.f_sender.to_le();
        msg.f_receiver = msg.f_receiver.to_le();

        // check type and reserved fields

        if msg.f_type != (TYPE_RESPONSE as u32) {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        Ok(msg)
    }
}

impl Into<Vec<u8>> for Response {
    fn into(self) -> Vec<u8> {
        // correct endianness
        let mut msg = self;
        msg.f_type = msg.f_type.to_le();
        msg.f_sender = msg.f_sender.to_le();
        msg.f_receiver = msg.f_receiver.to_le();

        // cast to array
        let array : [u8; mem::size_of::<Self>()];
        unsafe {
            array = mem::transmute::<Self, [u8; mem::size_of::<Self>()]>(msg)
        };

        array.to_vec()
    }
}

impl Default for Response {
    fn default() -> Self {
        Self {
            f_type      : TYPE_RESPONSE as u32,
            f_sender    : 0,
            f_receiver  : 0,
            f_ephemeral : [0u8; SIZE_X25519_POINT],
            f_empty_tag : [0u8; SIZE_TAG]
        }
    }
}

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
        self.f_type == other.f_type &&
        self.f_sender == other.f_sender &&
        self.f_receiver == other.f_receiver &&
        self.f_ephemeral == other.f_ephemeral &&
        self.f_empty_tag == other.f_empty_tag
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_response_identity() {
        let mut msg : Response = Default::default();

        msg.f_sender = 146252;
        msg.f_receiver = 554442;
        msg.f_ephemeral = [
            0xc1, 0x66, 0x0a, 0x0c, 0xdc, 0x0f, 0x6c, 0x51,
            0x0f, 0xc2, 0xcc, 0x51, 0x52, 0x0c, 0xde, 0x1e,
            0xf7, 0xf1, 0xca, 0x90, 0x86, 0x72, 0xad, 0x67,
            0xea, 0x89, 0x45, 0x44, 0x13, 0x56, 0x52, 0x1f
        ];
        msg.f_empty_tag = [
            0x60, 0x0e, 0x1e, 0x95, 0x41, 0x6b, 0x52, 0x05,
            0xa2, 0x09, 0xe1, 0xbf, 0x40, 0x05, 0x2f, 0xde
        ];

        let buf : Vec<u8> = msg.into();
        let msg_p : Response = Response::try_from(&buf[..]).unwrap();
        assert_eq!(msg, msg_p);
    }

    #[test]
    fn message_initiate_identity() {
        let mut msg : Initiation = Default::default();

        msg.f_sender = 575757;
        msg.f_ephemeral = [
            0xc1, 0x66, 0x0a, 0x0c, 0xdc, 0x0f, 0x6c, 0x51,
            0x0f, 0xc2, 0xcc, 0x51, 0x52, 0x0c, 0xde, 0x1e,
            0xf7, 0xf1, 0xca, 0x90, 0x86, 0x72, 0xad, 0x67,
            0xea, 0x89, 0x45, 0x44, 0x13, 0x56, 0x52, 0x1f
        ];
        msg.f_static = [
            0xdc, 0x33, 0x90, 0x15, 0x8f, 0x82, 0x3e, 0x06,
            0x44, 0xa0, 0xde, 0x4c, 0x15, 0x6c, 0x5d, 0xa4,
            0x65, 0x99, 0xf6, 0x6c, 0xa1, 0x14, 0x77, 0xf9,
            0xeb, 0x6a, 0xec, 0xc3, 0x3c, 0xda, 0x47, 0xe1
        ];
        msg.f_static_tag = [
            0x45, 0xac, 0x8d, 0x43, 0xea, 0x1b, 0x2f, 0x02,
            0x45, 0x5d, 0x86, 0x37, 0xee, 0x83, 0x6b, 0x42
        ];
        msg.f_timestamp = [
            0x4f, 0x1c, 0x60, 0xec, 0x0e, 0xf6, 0x36, 0xf0,
            0x78, 0x28, 0x57, 0x42
        ];
        msg.f_timestamp_tag = [
            0x60, 0x0e, 0x1e, 0x95, 0x41, 0x6b, 0x52, 0x05,
            0xa2, 0x09, 0xe1, 0xbf, 0x40, 0x05, 0x2f, 0xde
        ];

        let buf : Vec<u8> = msg.into();
        assert_eq!(msg, Initiation::try_from(&buf[..]).unwrap());
    }
}
