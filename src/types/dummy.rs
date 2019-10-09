use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;
use std::marker;

use super::*;

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

/* TUN implementation */

#[derive(Debug)]
pub enum TunError {}

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
}

impl UnitEndpoint {
    pub fn new() -> UnitEndpoint {
        UnitEndpoint{}
    }
}

/* */

#[derive(Clone, Copy)]
pub struct TunTest {}

impl tun::Reader for TunTest {
    type Error = TunError;

    fn read(&self, _buf: &mut [u8], _offset: usize) -> Result<usize, Self::Error> {
        Ok(0)
    }
}

impl tun::MTU for TunTest {
    fn mtu(&self) -> usize {
        1500
    }
}

impl tun::Writer for TunTest {
    type Error = TunError;

    fn write(&self, _src: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl tun::Tun for TunTest {
    type Writer = TunTest;
    type Reader = TunTest;
    type MTU = TunTest;
    type Error = TunError;
}

impl TunTest {
    pub fn create(_name: &str) -> Result<(TunTest, TunTest, TunTest), TunError> {
        Ok((TunTest {},TunTest {}, TunTest{}))
    }
}

/* Void Bind */

#[derive(Clone, Copy)]
pub struct VoidBind {}

impl bind::Reader<UnitEndpoint> for VoidBind {
    type Error = BindError;

    fn read(&self, _buf: &mut [u8]) -> Result<(usize, UnitEndpoint), Self::Error> {
        Ok((0, UnitEndpoint {}))
    }
}

impl bind::Writer<UnitEndpoint> for VoidBind {
    type Error = BindError;

    fn write(&self, _buf: &[u8], _dst: &UnitEndpoint) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl bind::Bind for VoidBind {
    type Error = BindError;
    type Endpoint = UnitEndpoint;

    type Reader = VoidBind;
    type Writer = VoidBind;
    type Closer = ();

    fn bind(_ : u16) -> Result<(Self::Reader, Self::Writer, Self::Closer, u16), Self::Error> {
        Ok((VoidBind{}, VoidBind{}, (), 2600))
    }
}

impl VoidBind {
    pub fn new() -> VoidBind {
        VoidBind{}
    }
}

/* Pair Bind */

#[derive(Clone)]
pub struct PairReader<E> {
    recv: Arc<Mutex<Receiver<Vec<u8>>>>,
    _marker: marker::PhantomData<E>,
}

impl bind::Reader<UnitEndpoint> for PairReader<UnitEndpoint> {
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

impl bind::Writer<UnitEndpoint> for PairWriter<UnitEndpoint> {
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
    pub fn pair<E>() -> ((PairReader<E>, PairWriter<E>), (PairReader<E>, PairWriter<E>)) {
        let (tx1, rx1) = sync_channel(128);
        let (tx2, rx2) = sync_channel(128);
        (
            (
                PairReader{ 
                    
                    recv: Arc::new(Mutex::new(rx1)), 
                    _marker: marker::PhantomData 
                }, 
                PairWriter{ 
                    send: Arc::new(Mutex::new(tx2)),
                    _marker: marker::PhantomData
                }
            ),
            (
                PairReader{ 
                    recv: Arc::new(Mutex::new(rx2)),
                    _marker: marker::PhantomData 
                }, 
                PairWriter{ 
                    send: Arc::new(Mutex::new(tx1)),
                    _marker: marker::PhantomData 
                }
            ),
        )
    }
}

impl bind::Bind for PairBind {
    type Closer = ();
    type Error = BindError;
    type Endpoint = UnitEndpoint;
    type Reader = PairReader<Self::Endpoint>;
    type Writer = PairWriter<Self::Endpoint>;
    
    fn bind(_port: u16) -> Result<(Self::Reader, Self::Writer, Self::Closer, u16), Self::Error> {
        Err(BindError::Disconnected)
    }
}

pub fn keypair(initiator: bool) -> KeyPair {
    let k1 = Key {
        key: [0x53u8; 32],
        id: 0x646e6573,
    };
    let k2 = Key {
        key: [0x52u8; 32],
        id: 0x76636572,
    };
    if initiator {
        KeyPair {
            birth: Instant::now(),
            initiator: true,
            send: k1,
            recv: k2,
        }
    } else {
        KeyPair {
            birth: Instant::now(),
            initiator: false,
            send: k2,
            recv: k1,
        }
    }
}
