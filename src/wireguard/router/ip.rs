use core::mem;

use byteorder::BigEndian;
use zerocopy::byteorder::U16;
use zerocopy::LayoutVerified;
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

#[inline(always)]
pub fn inner_length(packet: &[u8]) -> Option<usize> {
    match packet.get(0)? >> 4 {
        VERSION_IP4 => {
            let (header, _): (LayoutVerified<&[u8], IPv4Header>, _) =
                LayoutVerified::new_from_prefix(packet)?;

            Some(header.f_total_len.get() as usize)
        }
        VERSION_IP6 => {
            // check length and cast to IPv6 header
            let (header, _): (LayoutVerified<&[u8], IPv6Header>, _) =
                LayoutVerified::new_from_prefix(packet)?;

            Some(header.f_len.get() as usize + mem::size_of::<IPv6Header>())
        }
        _ => None,
    }
}
