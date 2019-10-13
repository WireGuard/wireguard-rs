#[cfg(test)]
use hex;

#[cfg(test)]
use std::fmt;

use std::mem;

use byteorder::LittleEndian;
use zerocopy::byteorder::U32;
use zerocopy::{AsBytes, ByteSlice, FromBytes, LayoutVerified};

use super::types::*;

const SIZE_MAC: usize = 16;
const SIZE_TAG: usize = 16; // poly1305 tag
const SIZE_XNONCE: usize = 24; // xchacha20 nonce
const SIZE_COOKIE: usize = 16; //
const SIZE_X25519_POINT: usize = 32; // x25519 public key
const SIZE_TIMESTAMP: usize = 12;

pub const TYPE_INITIATION: u32 = 1;
pub const TYPE_RESPONSE: u32 = 2;
pub const TYPE_COOKIE_REPLY: u32 = 3;

const fn max(a: usize, b: usize) -> usize {
    let m: usize = (a > b) as usize;
    m * a + (1 - m) * b
}

pub const MAX_HANDSHAKE_MSG_SIZE: usize = max(
    max(mem::size_of::<Response>(), mem::size_of::<Initiation>()),
    mem::size_of::<CookieReply>(),
);

/* Handshake messsages */

#[repr(packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct Response {
    pub noise: NoiseResponse, // inner message covered by macs
    pub macs: MacsFooter,
}

#[repr(packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct Initiation {
    pub noise: NoiseInitiation, // inner message covered by macs
    pub macs: MacsFooter,
}

#[repr(packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct CookieReply {
    pub f_type: U32<LittleEndian>,
    pub f_receiver: U32<LittleEndian>,
    pub f_nonce: [u8; SIZE_XNONCE],
    pub f_cookie: [u8; SIZE_COOKIE + SIZE_TAG],
}

/* Inner sub-messages */

#[repr(packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct MacsFooter {
    pub f_mac1: [u8; SIZE_MAC],
    pub f_mac2: [u8; SIZE_MAC],
}

#[repr(packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct NoiseInitiation {
    pub f_type: U32<LittleEndian>,
    pub f_sender: U32<LittleEndian>,
    pub f_ephemeral: [u8; SIZE_X25519_POINT],
    pub f_static: [u8; SIZE_X25519_POINT + SIZE_TAG],
    pub f_timestamp: [u8; SIZE_TIMESTAMP + SIZE_TAG],
}

#[repr(packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct NoiseResponse {
    pub f_type: U32<LittleEndian>,
    pub f_sender: U32<LittleEndian>,
    pub f_receiver: U32<LittleEndian>,
    pub f_ephemeral: [u8; SIZE_X25519_POINT],
    pub f_empty: [u8; SIZE_TAG],
}

/* Zero copy parsing of handshake messages */

impl Initiation {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<LayoutVerified<B, Self>, HandshakeError> {
        let msg: LayoutVerified<B, Self> =
            LayoutVerified::new(bytes).ok_or(HandshakeError::InvalidMessageFormat)?;

        if msg.noise.f_type.get() != (TYPE_INITIATION as u32) {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        Ok(msg)
    }
}

impl Response {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<LayoutVerified<B, Self>, HandshakeError> {
        let msg: LayoutVerified<B, Self> =
            LayoutVerified::new(bytes).ok_or(HandshakeError::InvalidMessageFormat)?;

        if msg.noise.f_type.get() != (TYPE_RESPONSE as u32) {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        Ok(msg)
    }
}

impl CookieReply {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<LayoutVerified<B, Self>, HandshakeError> {
        let msg: LayoutVerified<B, Self> =
            LayoutVerified::new(bytes).ok_or(HandshakeError::InvalidMessageFormat)?;

        if msg.f_type.get() != (TYPE_COOKIE_REPLY as u32) {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        Ok(msg)
    }
}

/* Default values */

impl Default for Response {
    fn default() -> Self {
        Self {
            noise: Default::default(),
            macs: Default::default(),
        }
    }
}

impl Default for Initiation {
    fn default() -> Self {
        Self {
            noise: Default::default(),
            macs: Default::default(),
        }
    }
}

impl Default for CookieReply {
    fn default() -> Self {
        Self {
            f_type: <U32<LittleEndian>>::new(TYPE_COOKIE_REPLY as u32),
            f_receiver: <U32<LittleEndian>>::ZERO,
            f_nonce: [0u8; SIZE_XNONCE],
            f_cookie: [0u8; SIZE_COOKIE + SIZE_TAG],
        }
    }
}

impl Default for MacsFooter {
    fn default() -> Self {
        Self {
            f_mac1: [0u8; SIZE_MAC],
            f_mac2: [0u8; SIZE_MAC],
        }
    }
}

impl Default for NoiseInitiation {
    fn default() -> Self {
        Self {
            f_type: <U32<LittleEndian>>::new(TYPE_INITIATION as u32),
            f_sender: <U32<LittleEndian>>::ZERO,
            f_ephemeral: [0u8; SIZE_X25519_POINT],
            f_static: [0u8; SIZE_X25519_POINT + SIZE_TAG],
            f_timestamp: [0u8; SIZE_TIMESTAMP + SIZE_TAG],
        }
    }
}

impl Default for NoiseResponse {
    fn default() -> Self {
        Self {
            f_type: <U32<LittleEndian>>::new(TYPE_RESPONSE as u32),
            f_sender: <U32<LittleEndian>>::ZERO,
            f_receiver: <U32<LittleEndian>>::ZERO,
            f_ephemeral: [0u8; SIZE_X25519_POINT],
            f_empty: [0u8; SIZE_TAG],
        }
    }
}

/* Debug formatting (for testing purposes) */

#[cfg(test)]
impl fmt::Debug for Initiation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Initiation {{ {:?} || {:?} }}", self.noise, self.macs)
    }
}

#[cfg(test)]
impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Response {{ {:?} || {:?} }}", self.noise, self.macs)
    }
}

#[cfg(test)]
impl fmt::Debug for CookieReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CookieReply {{ type = {}, receiver = {}, nonce = {}, cookie = {}  }}",
            self.f_type,
            self.f_receiver,
            hex::encode(&self.f_nonce[..]),
            hex::encode(&self.f_cookie[..]),
        )
    }
}

#[cfg(test)]
impl fmt::Debug for NoiseInitiation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "NoiseInitiation {{ type = {}, sender = {}, ephemeral = {}, static = {}, timestamp = {} }}",
            self.f_type.get(),
            self.f_sender.get(),
            hex::encode(&self.f_ephemeral[..]),
            hex::encode(&self.f_static[..]),
            hex::encode(&self.f_timestamp[..]),
        )
    }
}

#[cfg(test)]
impl fmt::Debug for NoiseResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "NoiseResponse {{ type = {}, sender = {}, receiver = {}, ephemeral = {}, empty = |{}  }}",
            self.f_type,
            self.f_sender,
            self.f_receiver,
            hex::encode(&self.f_ephemeral[..]),
            hex::encode(&self.f_empty[..])
        )
    }
}

#[cfg(test)]
impl fmt::Debug for MacsFooter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Macs {{ mac1 = {}, mac2 = {} }}",
            hex::encode(&self.f_mac1[..]),
            hex::encode(&self.f_mac2[..])
        )
    }
}

/* Equality (for testing purposes) */

#[cfg(test)]
macro_rules! eq_as_bytes {
    ($type:path) => {
        impl PartialEq for $type {
            fn eq(&self, other: &Self) -> bool {
                self.as_bytes() == other.as_bytes()
            }
        }
        impl Eq for $type {}
    };
}

#[cfg(test)]
eq_as_bytes!(Initiation);

#[cfg(test)]
eq_as_bytes!(Response);

#[cfg(test)]
eq_as_bytes!(CookieReply);

#[cfg(test)]
eq_as_bytes!(MacsFooter);

#[cfg(test)]
eq_as_bytes!(NoiseInitiation);

#[cfg(test)]
eq_as_bytes!(NoiseResponse);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_response_identity() {
        let mut msg: Response = Default::default();

        msg.noise.f_sender.set(146252);
        msg.noise.f_receiver.set(554442);
        msg.noise.f_ephemeral = [
            0xc1, 0x66, 0x0a, 0x0c, 0xdc, 0x0f, 0x6c, 0x51, 0x0f, 0xc2, 0xcc, 0x51, 0x52, 0x0c,
            0xde, 0x1e, 0xf7, 0xf1, 0xca, 0x90, 0x86, 0x72, 0xad, 0x67, 0xea, 0x89, 0x45, 0x44,
            0x13, 0x56, 0x52, 0x1f,
        ];
        msg.noise.f_empty = [
            0x60, 0x0e, 0x1e, 0x95, 0x41, 0x6b, 0x52, 0x05, 0xa2, 0x09, 0xe1, 0xbf, 0x40, 0x05,
            0x2f, 0xde,
        ];
        msg.macs.f_mac1 = [
            0xf2, 0xad, 0x40, 0xb5, 0xf7, 0xde, 0x77, 0x35, 0x89, 0x19, 0xb7, 0x5c, 0xf9, 0x54,
            0x69, 0x29,
        ];
        msg.macs.f_mac2 = [
            0x4f, 0xd2, 0x1b, 0xfe, 0x77, 0xe6, 0x2e, 0xc9, 0x07, 0xe2, 0x87, 0x17, 0xbb, 0xe5,
            0xdf, 0xbb,
        ];

        let buf: Vec<u8> = msg.as_bytes().to_vec();
        let msg_p = Response::parse(&buf[..]).unwrap();
        assert_eq!(msg, *msg_p.into_ref());
    }

    #[test]
    fn message_initiate_identity() {
        let mut msg: Initiation = Default::default();

        msg.noise.f_sender.set(575757);
        msg.noise.f_ephemeral = [
            0xc1, 0x66, 0x0a, 0x0c, 0xdc, 0x0f, 0x6c, 0x51, 0x0f, 0xc2, 0xcc, 0x51, 0x52, 0x0c,
            0xde, 0x1e, 0xf7, 0xf1, 0xca, 0x90, 0x86, 0x72, 0xad, 0x67, 0xea, 0x89, 0x45, 0x44,
            0x13, 0x56, 0x52, 0x1f,
        ];
        msg.noise.f_static = [
            0xdc, 0x33, 0x90, 0x15, 0x8f, 0x82, 0x3e, 0x06, 0x44, 0xa0, 0xde, 0x4c, 0x15, 0x6c,
            0x5d, 0xa4, 0x65, 0x99, 0xf6, 0x6c, 0xa1, 0x14, 0x77, 0xf9, 0xeb, 0x6a, 0xec, 0xc3,
            0x3c, 0xda, 0x47, 0xe1, 0x45, 0xac, 0x8d, 0x43, 0xea, 0x1b, 0x2f, 0x02, 0x45, 0x5d,
            0x86, 0x37, 0xee, 0x83, 0x6b, 0x42,
        ];
        msg.noise.f_timestamp = [
            0x4f, 0x1c, 0x60, 0xec, 0x0e, 0xf6, 0x36, 0xf0, 0x78, 0x28, 0x57, 0x42, 0x60, 0x0e,
            0x1e, 0x95, 0x41, 0x6b, 0x52, 0x05, 0xa2, 0x09, 0xe1, 0xbf, 0x40, 0x05, 0x2f, 0xde,
        ];
        msg.macs.f_mac1 = [
            0xf2, 0xad, 0x40, 0xb5, 0xf7, 0xde, 0x77, 0x35, 0x89, 0x19, 0xb7, 0x5c, 0xf9, 0x54,
            0x69, 0x29,
        ];
        msg.macs.f_mac2 = [
            0x4f, 0xd2, 0x1b, 0xfe, 0x77, 0xe6, 0x2e, 0xc9, 0x07, 0xe2, 0x87, 0x17, 0xbb, 0xe5,
            0xdf, 0xbb,
        ];

        let buf: Vec<u8> = msg.as_bytes().to_vec();
        let msg_p = Initiation::parse(&buf[..]).unwrap();
        assert_eq!(msg, *msg_p.into_ref());
    }
}
