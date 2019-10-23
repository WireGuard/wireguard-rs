#[cfg(test)]
use super::super::wireguard::dummy;
use super::BindOwner;
use super::PlatformBind;

pub struct VoidOwner {}

impl BindOwner for VoidOwner {
    type Error = dummy::BindError;

    fn set_fwmark(&self, value: Option<u32>) -> Option<Self::Error> {
        None
    }
}

impl PlatformBind for dummy::PairBind {
    type Owner = VoidOwner;

    fn bind(_port: u16) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error> {
        Err(dummy::BindError::Disconnected)
    }
}
