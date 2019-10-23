use std::error::Error;
use std::fmt;
use std::marker;
use std::net::SocketAddr;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::sync::Mutex;

use super::super::bind::*;
use super::super::Endpoint;

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

/* Endpoint implementation */

#[derive(Clone, Copy)]
pub struct UnitEndpoint {}

impl Endpoint for UnitEndpoint {
    fn from_address(_: SocketAddr) -> UnitEndpoint {
        UnitEndpoint {}
    }

    fn into_address(&self) -> SocketAddr {
        "127.0.0.1:8080".parse().unwrap()
    }

    fn clear_src(&mut self) {}
}

impl UnitEndpoint {
    pub fn new() -> UnitEndpoint {
        UnitEndpoint {}
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
        Ok((vec.len(), UnitEndpoint {}))
    }
}

impl Writer<UnitEndpoint> for PairWriter<UnitEndpoint> {
    type Error = BindError;
    fn write(&self, buf: &[u8], _dst: &UnitEndpoint) -> Result<(), Self::Error> {
        let owned = buf.to_owned();
        match self.send.lock().unwrap().send(owned) {
            Err(_) => Err(BindError::Disconnected),
            Ok(_) => Ok(()),
        }
    }
}

#[derive(Clone)]
pub struct PairWriter<E> {
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
        let (tx1, rx1) = sync_channel(128);
        let (tx2, rx2) = sync_channel(128);
        (
            (
                PairReader {
                    recv: Arc::new(Mutex::new(rx1)),
                    _marker: marker::PhantomData,
                },
                PairWriter {
                    send: Arc::new(Mutex::new(tx2)),
                    _marker: marker::PhantomData,
                },
            ),
            (
                PairReader {
                    recv: Arc::new(Mutex::new(rx2)),
                    _marker: marker::PhantomData,
                },
                PairWriter {
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

    fn set_fwmark(&self, _value: Option<u32>) -> Option<Self::Error> {
        None
    }
}

impl Platform for PairBind {
    type Owner = VoidOwner;
    fn bind(_port: u16) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error> {
        Err(BindError::Disconnected)
    }
}
