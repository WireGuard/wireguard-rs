use byteorder::BigEndian;
use zerocopy::byteorder::U16;
use zerocopy::{AsBytes, FromBytes};

pub const VERSION_IP4: u8 = 4;
pub const VERSION_IP6: u8 = 6;

#[repr(packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct IPv4Header {
    _f_space1: [u8; 2],
    pub f_total_len: U16<BigEndian>,
    _f_space2: [u8; 8],
    pub f_source: [u8; 4],
    pub f_destination: [u8; 4],
}

#[repr(packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct IPv6Header {
    _f_space1: [u8; 4],
    pub f_len: U16<BigEndian>,
    _f_space2: [u8; 2],
    pub f_source: [u8; 16],
    pub f_destination: [u8; 16],
}
