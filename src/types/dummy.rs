use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

use super::{Bind, Endpoint, Key, KeyPair, Tun};

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

#[derive(Clone, Copy)]
pub struct TunTest {}

impl Tun for TunTest {
    type Error = TunError;

    fn mtu(&self) -> usize {
        1500
    }

    fn read(&self, _buf: &mut [u8], _offset: usize) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn write(&self, _src: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl TunTest {
    pub fn new() -> TunTest {
        TunTest {}
    }
}

/* Bind implemenentations */

#[derive(Clone, Copy)]
pub struct VoidBind {}

impl Bind for VoidBind {
    type Error = BindError;
    type Endpoint = UnitEndpoint;

    fn new() -> VoidBind {
        VoidBind {}
    }

    fn set_port(&self, _port: u16) -> Result<(), Self::Error> {
        Ok(())
    }

    fn get_port(&self) -> Option<u16> {
        None
    }

    fn recv(&self, _buf: &mut [u8]) -> Result<(usize, Self::Endpoint), Self::Error> {
        Ok((0, UnitEndpoint {}))
    }

    fn send(&self, _buf: &[u8], _dst: &Self::Endpoint) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct PairBind {
    send: Arc<Mutex<SyncSender<Vec<u8>>>>,
    recv: Arc<Mutex<Receiver<Vec<u8>>>>,
}

impl PairBind {
    pub fn pair() -> (PairBind, PairBind) {
        let (tx1, rx1) = sync_channel(128);
        let (tx2, rx2) = sync_channel(128);
        (
            PairBind {
                send: Arc::new(Mutex::new(tx1)),
                recv: Arc::new(Mutex::new(rx2)),
            },
            PairBind {
                send: Arc::new(Mutex::new(tx2)),
                recv: Arc::new(Mutex::new(rx1)),
            },
        )
    }
}

impl Bind for PairBind {
    type Error = BindError;
    type Endpoint = UnitEndpoint;

    fn new() -> PairBind {
        PairBind {
            send: Arc::new(Mutex::new(sync_channel(0).0)),
            recv: Arc::new(Mutex::new(sync_channel(0).1)),
        }
    }

    fn set_port(&self, _port: u16) -> Result<(), Self::Error> {
        Ok(())
    }

    fn get_port(&self) -> Option<u16> {
        None
    }

    fn recv(&self, buf: &mut [u8]) -> Result<(usize, Self::Endpoint), Self::Error> {
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

    fn send(&self, buf: &[u8], _dst: &Self::Endpoint) -> Result<(), Self::Error> {
        let owned = buf.to_owned();
        match self.send.lock().unwrap().send(owned) {
            Err(_) => Err(BindError::Disconnected),
            Ok(_) => Ok(()),
        }
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
