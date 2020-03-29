use super::super::tun::*;

mod dummy;
mod void;

#[derive(Debug)]
pub enum TunError {
    Disconnected,
}

pub use dummy::*;
pub use void::*;
