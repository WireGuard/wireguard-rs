/*
// This code provides a "void" implementation of the tunnel interface:
// The implementation never reads and immediately discards any write without error
//
// This is used during benchmarking and profiling of the inbound path.

use super::*;

pub struct VoidTun {}

pub struct VoidReader {}

pub struct VoidWriter {}

impl Tun for VoidTun {
    type Writer = VoidWriter;
    type Reader = VoidReader;
    type Error = TunError;
}


impl Reader for VodReader {
    type Error = TunError;

    fn write(&self, src: &[u8]) -> Result<(), Self::Error> {
        debug!(
            "dummy::TUN({}) : write ({}, {})",
            self.id,
            src.len(),
            hex::encode(src)
        );
        if self.store {
            let m = src.to_owned();
            match self.tx.lock().unwrap().send(m) {
                Ok(_) => Ok(()),
                Err(_) => Err(TunError::Disconnected),
            }
        } else {
            Ok(())
        }
    }
}
*/
