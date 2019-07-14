use std::fmt;
use std::mem;

const SIZE_TAG : usize = 16;
const SIZE_X25519_POINT : usize = 32;
const SIZE_TIMESTAMP : usize = 12;

pub const TYPE_INITIATION : u8 = 1;
pub const TYPE_RESPONSE : u8 = 2;

/* Wireguard handshake initiation message
 * initator -> responder
 */
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Initiation {
    pub f_type      : u8,
    f_reserved      : [u8; 3],
    pub f_sender    : u32,
    pub f_ephemeral : [u8; SIZE_X25519_POINT],
    pub f_static    : [u8; SIZE_X25519_POINT + SIZE_TAG],
    pub f_timestamp : [u8; SIZE_TIMESTAMP + SIZE_TAG],
}

impl From<&[u8]> for Initiation {
    fn from(b: &[u8]) -> Self {
        // create owned copy
        let mut owned = [0u8; mem::size_of::<Self>()];
        let mut msg : Self;
        owned.copy_from_slice(b);

        // cast to Initiation
        unsafe {
            msg = mem::transmute::<[u8; mem::size_of::<Self>()], Self>(owned);
        };

        // correct endianness
        msg.f_type = msg.f_type.to_le();
        msg.f_sender = msg.f_sender.to_le();
        msg
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

impl fmt::Debug for Initiation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "MessageInitiation {{ type = {} }}",
            self.f_type
        )
    }
}

impl Default for Initiation {
    fn default() -> Self {
        Self {
            f_type      : TYPE_INITIATION,
            f_reserved  : [0u8; 3],
            f_sender    : 0,
            f_ephemeral : [0u8; SIZE_X25519_POINT],
            f_static    : [0u8; SIZE_X25519_POINT + SIZE_TAG],
            f_timestamp : [0u8; SIZE_TIMESTAMP + SIZE_TAG],
        }
    }
}

#[cfg(test)]
impl PartialEq for Initiation {
    fn eq(&self, other: &Self) -> bool {
        self.f_type == other.f_type &&
        self.f_reserved == other.f_reserved &&
        self.f_sender == other.f_sender &&
        self.f_ephemeral[..] == other.f_ephemeral[..] &&
        self.f_static[..] == other.f_static[..] &&
        self.f_timestamp[..] == other.f_timestamp
    }
}

#[cfg(test)]
impl Eq for Initiation {}


/* Wireguard handshake responder message
 * responder -> initator
 */
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Response {
    f_type      : u8,
    f_reserved  : [u8; 3],
    f_sender    : u32,
    f_receiver  : u32,
    f_ephemeral : [u8; SIZE_X25519_POINT],
    f_empty     : [u8; SIZE_TAG],
}

impl From<&[u8]> for Response {
    fn from(b: &[u8]) -> Self {
        // create owned copy
        let mut owned = [0u8; mem::size_of::<Self>()];
        let mut msg : Self;
        owned.copy_from_slice(b);

        // cast to MessageResponse
        unsafe {
            msg = mem::transmute::<[u8; mem::size_of::<Self>()], Self>(owned);
        };

        // correct endianness
        msg.f_type = msg.f_type.to_le();
        msg.f_sender = msg.f_sender.to_le();
        msg.f_receiver = msg.f_receiver.to_le();
        msg
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

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "MessageResponse {{ type = {} }}",
            self.f_type
        )
    }
}

#[cfg(test)]
impl PartialEq for Response {
    fn eq(&self, other: &Self) -> bool {
        self.f_type == other.f_type &&
        self.f_reserved == other.f_reserved &&
        self.f_sender == other.f_sender &&
        self.f_receiver == other.f_receiver &&
        self.f_ephemeral == other.f_ephemeral &&
        self.f_empty == other.f_empty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_response_identity() {
        let msg = Response {
            f_type      : TYPE_RESPONSE,
            f_reserved  : [0u8; 3],
            f_sender    : 146252,
            f_receiver  : 554442,
            f_ephemeral : [
                // ephemeral public key
                0xc1, 0x66, 0x0a, 0x0c, 0xdc, 0x0f, 0x6c, 0x51,
                0x0f, 0xc2, 0xcc, 0x51, 0x52, 0x0c, 0xde, 0x1e,
                0xf7, 0xf1, 0xca, 0x90, 0x86, 0x72, 0xad, 0x67,
                0xea, 0x89, 0x45, 0x44, 0x13, 0x56, 0x52, 0x1f
            ],
            f_empty : [
                // tag
                0x60, 0x0e, 0x1e, 0x95, 0x41, 0x6b, 0x52, 0x05,
                0xa2, 0x09, 0xe1, 0xbf, 0x40, 0x05, 0x2f, 0xde
            ]
        };

        let buf : Vec<u8> = msg.into();
        assert_eq!(msg, Response::from(&buf[..]));
    }

    #[test]
    fn message_initiate_identity() {
        let msg = Initiation {
            f_type      : TYPE_RESPONSE,
            f_reserved  : [0u8; 3],
            f_sender    : 575757,
            f_ephemeral : [
                // ephemeral public key
                0xc1, 0x66, 0x0a, 0x0c, 0xdc, 0x0f, 0x6c, 0x51,
                0x0f, 0xc2, 0xcc, 0x51, 0x52, 0x0c, 0xde, 0x1e,
                0xf7, 0xf1, 0xca, 0x90, 0x86, 0x72, 0xad, 0x67,
                0xea, 0x89, 0x45, 0x44, 0x13, 0x56, 0x52, 0x1f
            ],
            f_static    : [
                // encrypted static public key
                0xdc, 0x33, 0x90, 0x15, 0x8f, 0x82, 0x3e, 0x06,
                0x44, 0xa0, 0xde, 0x4c, 0x15, 0x6c, 0x5d, 0xa4,
                0x65, 0x99, 0xf6, 0x6c, 0xa1, 0x14, 0x77, 0xf9,
                0xeb, 0x6a, 0xec, 0xc3, 0x3c, 0xda, 0x47, 0xe1,

                // tag
                0x45, 0xac, 0x8d, 0x43, 0xea, 0x1b, 0x2f, 0x02,
                0x45, 0x5d, 0x86, 0x37, 0xee, 0x83, 0x6b, 0x42
            ],
            f_timestamp : [
                // timestamp
                0x4f, 0x1c, 0x60, 0xec, 0x0e, 0xf6, 0x36, 0xf0,
                0x78, 0x28, 0x57, 0x42,

                // tag
                0x60, 0x0e, 0x1e, 0x95, 0x41, 0x6b, 0x52, 0x05,
                0xa2, 0x09, 0xe1, 0xbf, 0x40, 0x05, 0x2f, 0xde
            ]
        };

        let buf : Vec<u8> = msg.into();
        assert_eq!(msg, Initiation::from(&buf[..]));
    }
}
