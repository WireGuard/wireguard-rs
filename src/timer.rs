use consts::TIMER_RESOLUTION;
use futures::{Future, Stream, Sink, Poll, unsync};
use std::time::Duration;
use tokio_core::reactor::Handle;
use tokio_timer;
use interface::SharedPeer;

#[derive(Debug)]
pub enum TimerMessage {
    PersistentKeepAlive(SharedPeer, u32),
    PassiveKeepAlive(SharedPeer, u32),
    Rekey(SharedPeer, u32),
    Wipe(SharedPeer),
}

pub struct Timer {
    handle: Handle,
    timer: tokio_timer::Timer,
    tx: unsync::mpsc::Sender<TimerMessage>,
    rx: unsync::mpsc::Receiver<TimerMessage>,
}

impl Timer {
    pub fn new(handle: Handle) -> Self {
        let (tx, rx) = unsync::mpsc::channel::<TimerMessage>(1024);
        let timer = tokio_timer::wheel()
            .tick_duration(*TIMER_RESOLUTION)
            .num_slots(1 << 14)
            .build();
        Self { handle, timer, tx, rx }
    }

    pub fn send_after(&mut self, delay: Duration, message: TimerMessage) {
        trace!("queuing timer message {:?}", &message);
        let timer = self.timer.sleep(delay + (*TIMER_RESOLUTION * 2));
        let future = timer.and_then({
            let tx = self.tx.clone();
            move |_| {
                tx.clone().send(message).then(|_| Ok(()))
            }
        }).then(|_| Ok(()));
        self.handle.spawn(future);
    }

}

impl Stream for Timer {
    type Item = TimerMessage;
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.rx.poll()
    }
}
