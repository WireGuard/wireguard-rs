use hex;
use log::debug;
use rand::rngs::OsRng;
use rand::Rng;

use std::cmp::min;
use std::error::Error;
use std::fmt;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use super::super::tun::*;

#[derive(Debug)]
pub enum TunError {
    Disconnected,
}

pub struct TunTest {}

pub struct TunFakeIO {
    id: u32,
    store: bool,
    tx: SyncSender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

pub struct TunReader {
    id: u32,
    rx: Receiver<Vec<u8>>,
}

pub struct TunWriter {
    id: u32,
    store: bool,
    tx: Mutex<SyncSender<Vec<u8>>>,
}

impl fmt::Display for TunFakeIO {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FakeIO({})", self.id)
    }
}

impl fmt::Display for TunReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TunReader({})", self.id)
    }
}

impl fmt::Display for TunWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TunWriter({})", self.id)
    }
}

pub struct TunStatus {
    first: bool,
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

impl Reader for TunReader {
    type Error = TunError;

    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Self::Error> {
        match self.rx.recv() {
            Ok(msg) => {
                let n = min(buf.len() - offset, msg.len());
                buf[offset..offset + n].copy_from_slice(&msg[..n]);
                debug!(
                    "dummy::TUN({}) : read ({}, {})",
                    self.id,
                    n,
                    hex::encode(&buf[offset..offset + n])
                );
                Ok(n)
            }
            Err(_) => Err(TunError::Disconnected),
        }
    }
}

impl Writer for TunWriter {
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

impl Status for TunStatus {
    type Error = TunError;

    fn event(&mut self) -> Result<TunEvent, Self::Error> {
        if self.first {
            self.first = false;
            return Ok(TunEvent::Up(1420));
        }

        loop {
            thread::sleep(Duration::from_secs(60 * 60));
        }
    }
}

impl Tun for TunTest {
    type Writer = TunWriter;
    type Reader = TunReader;
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
    pub fn create(store: bool) -> (TunFakeIO, TunReader, TunWriter, TunStatus) {
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

        let mut rng = OsRng::new().unwrap();
        let id: u32 = rng.gen();

        let fake = TunFakeIO {
            id,
            tx: tx1,
            rx: rx2,
            store,
        };
        let reader = TunReader { id, rx: rx1 };
        let writer = TunWriter {
            id,
            tx: Mutex::new(tx2),
            store,
        };
        let status = TunStatus { first: true };
        (fake, reader, writer, status)
    }
}

impl PlatformTun for TunTest {
    type Status = TunStatus;

    fn create(_name: &str) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Status), Self::Error> {
        Err(TunError::Disconnected)
    }
}
