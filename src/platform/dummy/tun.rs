use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::sync::Mutex;

use super::super::tun::*;

/* This submodule provides pure/dummy implementations of the IO interfaces
 * for use in unit tests thoughout the project.
 */

/* Error implementation */

#[derive(Debug)]
pub enum BindError {
    Disconnected,
}

impl Error for BindError {
    fn description(&self) -> &str {
        "Generic Bind Error"
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindError::Disconnected => write!(f, "PairBind disconnected"),
        }
    }
}

#[derive(Debug)]
pub enum TunError {
    Disconnected,
}

impl Error for TunError {
    fn description(&self) -> &str {
        "Generic Tun Error"
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for TunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Not Possible")
    }
}

pub struct TunTest {}

pub struct TunFakeIO {
    store: bool,
    tx: SyncSender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

pub struct TunReader {
    rx: Receiver<Vec<u8>>,
}

pub struct TunWriter {
    store: bool,
    tx: Mutex<SyncSender<Vec<u8>>>,
}

#[derive(Clone)]
pub struct TunMTU {
    mtu: Arc<AtomicUsize>,
}

impl Reader for TunReader {
    type Error = TunError;

    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Self::Error> {
        match self.rx.recv() {
            Ok(m) => {
                buf[offset..].copy_from_slice(&m[..]);
                Ok(m.len())
            }
            Err(_) => Err(TunError::Disconnected),
        }
    }
}

impl Writer for TunWriter {
    type Error = TunError;

    fn write(&self, src: &[u8]) -> Result<(), Self::Error> {
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

impl MTU for TunMTU {
    fn mtu(&self) -> usize {
        self.mtu.load(Ordering::Acquire)
    }
}

impl Tun for TunTest {
    type Writer = TunWriter;
    type Reader = TunReader;
    type MTU = TunMTU;
    type Error = TunError;
}

impl TunFakeIO {
    pub fn write(&self, msg: Vec<u8>) {
        if self.store {
            self.tx.send(msg).unwrap();
        }
    }

    pub fn read(&self) -> Vec<u8> {
        self.rx.recv().unwrap()
    }
}

impl TunTest {
    pub fn create(mtu: usize, store: bool) -> (TunFakeIO, TunReader, TunWriter, TunMTU) {
        let (tx1, rx1) = if store {
            sync_channel(32)
        } else {
            sync_channel(1)
        };
        let (tx2, rx2) = if store {
            sync_channel(32)
        } else {
            sync_channel(1)
        };

        let fake = TunFakeIO {
            tx: tx1,
            rx: rx2,
            store,
        };
        let reader = TunReader { rx: rx1 };
        let writer = TunWriter {
            tx: Mutex::new(tx2),
            store,
        };
        let mtu = TunMTU {
            mtu: Arc::new(AtomicUsize::new(mtu)),
        };

        (fake, reader, writer, mtu)
    }
}

impl Platform for TunTest {
    fn create(_name: &str) -> Result<(Vec<Self::Reader>, Self::Writer, Self::MTU), Self::Error> {
        Err(TunError::Disconnected)
    }
}
