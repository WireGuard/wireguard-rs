use std::mem;

const SIZE_TAG : usize = 16;
const SIZE_X25519_POINT : usize = 32;
const SIZE_TIMESTAMP : usize = 12;

pub const SIZE_MESSAGE_INITIATE : usize = 116;
pub const SIZE_MESSAGE_RESPONSE : usize = 116;

pub const TYPE_INITIATE : u8 = 1;
pub const TYPE_RESPONSE : u8 = 2;

/* Wireguard handshake initiation message
 * initator -> responder
 */
#[repr(C)]
#[derive(Copy, Clone)]
struct MessageInitiate {
    f_type      : u32,
    f_sender    : u32,
    f_ephemeral : [u8; SIZE_X25519_POINT],
    f_static    : [u8; SIZE_X25519_POINT + SIZE_TAG],
    f_timestamp : [u8; SIZE_TIMESTAMP + SIZE_TAG],
}

impl From<&[u8]> for MessageInitiate {
    fn from(b: &[u8]) -> Self {
        // create owned copy
        let mut owned = [0u8; mem::size_of::<Self>()];
        let mut msg : Self;
        owned.copy_from_slice(b);

        // cast to MessageInitiate
        unsafe {
            msg = mem::transmute::<[u8; mem::size_of::<Self>()], Self>(owned);
        };

        // correct endianness
        msg.f_type = msg.f_type.to_le();
        msg.f_sender = msg.f_sender.to_le();
        msg
    }
}

impl Into<Vec<u8>> for MessageInitiate {
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

/* Wireguard handshake responder message
 * responder -> initator
 */
#[repr(C)]
#[derive(Copy, Clone)]
struct MessageResponse {
    f_type      : u32,
    f_sender    : u32,
    f_receiver  : u32,
    f_ephemeral : [u8; SIZE_X25519_POINT],
    f_empty     : [u8; SIZE_TAG],
}

impl From<&[u8]> for MessageResponse {
    fn from(b: &[u8]) -> Self {
        // create owned copy
        let mut owned = [0u8; mem::size_of::<Self>()];
        let mut msg : Self;
        owned.copy_from_slice(b);

        // cast to MessageInitiate
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

impl Into<Vec<u8>> for MessageResponse {
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
