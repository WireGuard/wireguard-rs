use super::super::{tun, udp, Endpoint};
use super::types::Callbacks;

use super::queue::ParallelJob;
use super::receive::ReceiveJob;
use super::send::SendJob;

use crossbeam_channel::Receiver;

pub enum JobUnion<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    Outbound(SendJob<E, C, T, B>),
    Inbound(ReceiveJob<E, C, T, B>),
}

pub fn worker<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
    receiver: Receiver<JobUnion<E, C, T, B>>,
) {
    loop {
        match receiver.recv() {
            Err(_) => break,
            Ok(JobUnion::Inbound(job)) => {
                job.parallel_work();
                job.queue().consume();
            }
            Ok(JobUnion::Outbound(job)) => {
                job.parallel_work();
                job.queue().consume();
            }
        }
    }
}
