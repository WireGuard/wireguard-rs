use consts::TIMER_RESOLUTION;
use futures::{Future, Stream, Sink, Poll, unsync};
use std::{cell::RefCell, rc::Rc};
use std::time::{Instant, Duration};
use tokio::timer::Delay;
use tokio_core::reactor::Handle;
use interface::SharedPeer;

#[derive(Debug)]
pub enum TimerMessage {
    PersistentKeepAlive(SharedPeer),
    PassiveKeepAlive(SharedPeer),
    Rekey(SharedPeer, u32),
    Wipe(SharedPeer),
}

pub struct TimerHandle {
    canceled: Rc<RefCell<bool>>
}

impl TimerHandle {
    pub fn cancel(&mut self) {
        *self.canceled.borrow_mut() = true;
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
        let canceled = Rc::new(RefCell::new(false));
        let handle = self.handle.clone();
        let tx = self.tx.clone();
        let future = Delay::new(Instant::now() + delay + (*TIMER_RESOLUTION * 2))
            .map_err(|e| panic!("timer failed; err={:?}", e))
            .and_then({
                let canceled = canceled.clone();
                move |_| {
                    if !*canceled.borrow() {
                        handle.spawn(tx.send(message).then(|_| Ok(())))
                    } else {
                        debug!("timer cancel signal sent, won't send message.");
                    }
                Ok(())
            }});
        self.handle.spawn(future);
        TimerHandle { canceled }
    }
}

impl Stream for Timer {
    type Item = TimerMessage;
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.rx.poll()
    }
}
