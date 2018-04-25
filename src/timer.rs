use consts::TIMER_RESOLUTION;
use futures::{Async, Future, Stream, Sink, Poll, unsync};
use std::time::{Instant, Duration};
use tokio::timer::Delay;
use tokio_core::reactor::Handle;
use interface::SharedPeer;

#[derive(Debug)]
pub enum TimerMessage {
    PersistentKeepAlive(SharedPeer, u32),
    PassiveKeepAlive(SharedPeer, u32),
    Rekey(SharedPeer, u32),
    Wipe(SharedPeer),
}

pub struct TimerHandle {
    tx: unsync::oneshot::Sender<()>
}

impl TimerHandle {
    pub fn cancel(self) -> Result<(), ()> {
        self.tx.send(())
    }
}

pub struct Timer {
    handle: Handle,
    tx: unsync::mpsc::Sender<TimerMessage>,
    rx: unsync::mpsc::Receiver<TimerMessage>,
}

impl Timer {
    pub fn new(handle: Handle) -> Self {
        let (tx, rx) = unsync::mpsc::channel::<TimerMessage>(1024);
        Self { handle, tx, rx }
    }

    pub fn send_after(&mut self, delay: Duration, message: TimerMessage) -> TimerHandle {
        trace!("queuing timer message {:?}", &message);
        let (cancel_tx, mut cancel_rx) = unsync::oneshot::channel();
        let tx = self.tx.clone();
        let future = Delay::new(Instant::now() + delay + (*TIMER_RESOLUTION * 2))
            .map_err(|e| panic!("timer failed; err={:?}", e))
            .and_then(move |_| {
                if let Ok(Async::Ready(())) = cancel_rx.poll() {
                    trace!("timer cancel signal sent, won't send message.");
                }
                tx.send(message).then(|_| Ok(())) 
            });
        self.handle.spawn(future);
        TimerHandle { tx: cancel_tx }
    }
}

impl Stream for Timer {
    type Item = TimerMessage;
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.rx.poll()
    }
}
