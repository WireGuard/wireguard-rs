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
}

pub struct Timer {
    timer: tokio_timer::Timer,
    tx: unsync::mpsc::Sender<TimerMessage>,
    rx: unsync::mpsc::Receiver<TimerMessage>,
}

impl Timer {
    pub fn new() -> Self {
        let (tx, rx) = unsync::mpsc::channel::<TimerMessage>(1024);
        let timer = tokio_timer::Timer::default();
        Self { timer, tx, rx }
    }

    pub fn spawn_delayed(&mut self, handle: &Handle, delay: Duration, message: TimerMessage) {
        trace!("queuing timer message {:?}", &message);
        let timer = self.timer.sleep(delay);
        let future = timer.and_then({
            let tx = self.tx.clone();
            move |_| {
                tx.clone().send(message).then(|_| Ok(()))
            }
        }).then(|_| Ok(()));
        handle.spawn(future);
    }

    pub fn spawn_immediately(&mut self, handle: &Handle, message: TimerMessage) {
       handle.spawn(self.tx.clone().send(message).then(|_| Ok(())));
    }
}

impl Stream for Timer {
    type Item = TimerMessage;
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.rx.poll()
    }
}
