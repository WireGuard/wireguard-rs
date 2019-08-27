use byteorder::LittleEndian;
use zerocopy::byteorder::{U32, U64};
use zerocopy::{AsBytes, ByteSlice, FromBytes, LayoutVerified};

#[repr(packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct TransportHeader {
    pub f_type: U32<LittleEndian>,
    pub f_receiver: U32<LittleEndian>,
    pub f_counter: U64<LittleEndian>
}