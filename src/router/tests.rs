use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;

use super::super::types::{Bind, Tun};
use super::{Device, Peer, SIZE_MESSAGE_PREFIX};

#[derive(Debug)]
enum TunError {}

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

struct TunTest {}

impl Tun for TunTest {
    type Error = TunError;

    fn mtu(&self) -> usize {
        1500
    }

    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Self::Error> {
        Ok(0)
    }

    fn write(&self, src: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct BindTest {}

impl Bind for BindTest {
    type Error = BindError;
    type Endpoint = SocketAddr;

    fn new() -> BindTest {
        BindTest {}
    }

    fn set_port(&self, port: u16) -> Result<(), Self::Error> {
        Ok(())
    }

    fn get_port(&self) -> Option<u16> {
        None
    }

    fn recv(&self, buf: &mut [u8]) -> Result<(usize, Self::Endpoint), Self::Error> {
        Ok((0, "127.0.0.1:8080".parse().unwrap()))
    }

    fn send(&self, buf: &[u8], dst: &Self::Endpoint) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug)]
enum BindError {}

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
        write!(f, "Not Possible")
    }
}

#[test]
fn test_outbound() {
    let opaque = Arc::new(AtomicBool::new(false));

    // create device (with Opaque = ())
    let workers = 4;
    let router = Device::new(
        workers,
        TunTest {},
        BindTest {},
        |t: &Arc<AtomicBool>, data: bool, sent: bool| {},
        |t: &Arc<AtomicBool>, data: bool, sent: bool| {},
        |t: &Arc<AtomicBool>| t.store(true, Ordering::SeqCst),
    );

    // create peer
    let peer = router.new_peer(opaque.clone());
    let tests = vec![
        ("192.168.1.0", 24, "192.168.1.20", true),
        ("172.133.133.133", 32, "172.133.133.133", true),
        ("172.133.133.133", 32, "172.133.133.132", false),
        (
            "2001:db8::ff00:42:0000",
            112,
            "2001:db8::ff00:42:3242",
            true,
        ),
        (
            "2001:db8::ff00:42:8000",
            113,
            "2001:db8::ff00:42:0660",
            false,
        ),
        (
            "2001:db8::ff00:42:8000",
            113,
            "2001:db8::ff00:42:ffff",
            true,
        ),
    ];

    for (mask, len, ip, okay) in &tests {
        opaque.store(false, Ordering::SeqCst);

        let mask: IpAddr = mask.parse().unwrap();

        // map subnet to peer
        peer.add_subnet(mask, *len);

        // create "IP packet"
        let mut msg = Vec::<u8>::new();
        msg.resize(SIZE_MESSAGE_PREFIX + 1024, 0);
        if mask.is_ipv4() {
            let mut packet = MutableIpv4Packet::new(&mut msg[SIZE_MESSAGE_PREFIX..]).unwrap();
            packet.set_destination(ip.parse().unwrap());
            packet.set_version(4);
        } else {
            let mut packet = MutableIpv6Packet::new(&mut msg[SIZE_MESSAGE_PREFIX..]).unwrap();
            packet.set_destination(ip.parse().unwrap());
            packet.set_version(6);
        }

        // cryptkey route the IP packet
        let res = router.send(msg);
        if *okay {
            // cryptkey routing succeeded
            assert!(res.is_ok());

            // and a key should have been requested
            assert!(opaque.load(Ordering::Acquire));
        } else {
            assert!(res.is_err());
        }

        // clear subnets for next test
        peer.remove_subnets();
    }
}
