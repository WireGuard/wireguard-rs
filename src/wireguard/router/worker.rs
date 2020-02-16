use super::Device;

use super::super::{tun, udp, Endpoint};
use super::types::Callbacks;

use super::receive::ReceieveJob;
use super::send::SendJob;

fn worker<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
    device: Device<E, C, T, B>,
) {
    // fetch job
}
