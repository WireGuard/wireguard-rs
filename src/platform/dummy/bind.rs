use hex;
use std::error::Error;
use std::fmt;
use std::marker;

use log::debug;
use rand::rngs::OsRng;
use rand::Rng;

use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::sync::Mutex;

use super::super::bind::*;

use super::UnitEndpoint;

pub struct VoidOwner {}

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

/* TUN implementation */

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

#[derive(Clone, Copy)]
pub struct VoidBind {}

impl Reader<UnitEndpoint> for VoidBind {
    type Error = BindError;

    fn read(&self, _buf: &mut [u8]) -> Result<(usize, UnitEndpoint), Self::Error> {
        Ok((0, UnitEndpoint {}))
    }
}

impl Writer<UnitEndpoint> for VoidBind {
    type Error = BindError;

    fn write(&self, _buf: &[u8], _dst: &UnitEndpoint) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Bind for VoidBind {
    type Error = BindError;
    type Endpoint = UnitEndpoint;

    type Reader = VoidBind;
    type Writer = VoidBind;
}

impl VoidBind {
    pub fn new() -> VoidBind {
        VoidBind {}
    }
}

/* Pair Bind */

#[derive(Clone)]
pub struct PairReader<E> {
    id: u32,
    recv: Arc<Mutex<Receiver<Vec<u8>>>>,
    _marker: marker::PhantomData<E>,
}

impl Reader<UnitEndpoint> for PairReader<UnitEndpoint> {
    type Error = BindError;
    fn read(&self, buf: &mut [u8]) -> Result<(usize, UnitEndpoint), Self::Error> {
        let vec = self
            .recv
            .lock()
            .unwrap()
            .recv()
            .map_err(|_| BindError::Disconnected)?;
        let len = vec.len();
        buf[..len].copy_from_slice(&vec[..]);
        debug!(
            "dummy({}): read ({}, {})",
            self.id,
            len,
            hex::encode(&buf[..len])
        );
        Ok((len, UnitEndpoint {}))
    }
}

impl Writer<UnitEndpoint> for PairWriter<UnitEndpoint> {
    type Error = BindError;
    fn write(&self, buf: &[u8], _dst: &UnitEndpoint) -> Result<(), Self::Error> {
        debug!(
            "dummy({}): write ({}, {})",
            self.id,
            buf.len(),
            hex::encode(buf)
        );
        let owned = buf.to_owned();
        match self.send.lock().unwrap().send(owned) {
            Err(_) => Err(BindError::Disconnected),
            Ok(_) => Ok(()),
        }
    }
}

#[derive(Clone)]
pub struct PairWriter<E> {
    id: u32,
    send: Arc<Mutex<SyncSender<Vec<u8>>>>,
    _marker: marker::PhantomData<E>,
}

#[derive(Clone)]
pub struct PairBind {}

impl PairBind {
    pub fn pair<E>() -> (
        (PairReader<E>, PairWriter<E>),
        (PairReader<E>, PairWriter<E>),
    ) {
        let mut rng = OsRng::new().unwrap();
        let id1: u32 = rng.gen();
        let id2: u32 = rng.gen();

        let (tx1, rx1) = sync_channel(128);
        let (tx2, rx2) = sync_channel(128);
        (
            (
                PairReader {
                    id: id1,
                    recv: Arc::new(Mutex::new(rx1)),
                    _marker: marker::PhantomData,
                },
                PairWriter {
                    id: id1,
                    send: Arc::new(Mutex::new(tx2)),
                    _marker: marker::PhantomData,
                },
            ),
            (
                PairReader {
                    id: id2,
                    recv: Arc::new(Mutex::new(rx2)),
                    _marker: marker::PhantomData,
                },
                PairWriter {
                    id: id2,
                    send: Arc::new(Mutex::new(tx1)),
                    _marker: marker::PhantomData,
                },
            ),
        )
    }
}

impl Bind for PairBind {
    type Error = BindError;
    type Endpoint = UnitEndpoint;
    type Reader = PairReader<Self::Endpoint>;
    type Writer = PairWriter<Self::Endpoint>;
}

impl Owner for VoidOwner {
    type Error = BindError;

    fn set_fwmark(&mut self, _value: Option<u32>) -> Option<Self::Error> {
        None
    }

    fn get_port(&self) -> u16 {
        0
    }

    fn get_fwmark(&self) -> Option<u32> {
        None
    }
}

impl PlatformBind for PairBind {
    type Owner = VoidOwner;
    fn bind(_port: u16) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error> {
        Err(BindError::Disconnected)
    }
}
