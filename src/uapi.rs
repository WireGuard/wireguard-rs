//! Mapping to the `WireGuard` user API

#![allow(dead_code)]

use std::convert::{AsMut, AsRef};
use std::fmt::{Debug, Result, Formatter};
use std::marker::PhantomData;
use std::mem::transmute;

use libc::{in_addr, in6_addr, sockaddr, sockaddr_in, sockaddr_in6, timeval};

const IFNAMSIZ: usize = 16;
const WG_KEY_LEN: usize = 32;

#[repr(C)]
#[derive(Clone)]
/// Represents a union field
pub struct UnionField<T>(PhantomData<T>);

impl<T> UnionField<T> {
    /// Creates a new `UnionField`
    pub fn new() -> Self {
        UnionField(PhantomData)
    }
}

impl<T: Clone> Copy for UnionField<T> {}

impl<T> AsRef<T> for UnionField<T> {
    fn as_ref(&self) -> &T {
        unsafe { transmute(self) }
    }
}

impl<T> AsMut<T> for UnionField<T> {
    fn as_mut(&mut self) -> &mut T {
        unsafe { transmute(self) }
    }
}


impl<T> Debug for UnionField<T> {
    fn fmt(&self, fmt: &mut Formatter) -> Result {
        fmt.write_str("Union")
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// A `WireGuard` device
pub struct WgDevice {
    /// The name of the interface
    pub interface: [u8; IFNAMSIZ],

    /// Interface flags
    pub flags: u32,

    /// The `WireGuard` public key
    pub public_key: [u8; WG_KEY_LEN],

    /// The `WireGuard` private key
    pub private_key: [u8; WG_KEY_LEN],

    /// The `WireGuard` pre-shared key
    pub preshared_key: [u8; WG_KEY_LEN],

    /// The wirewall mark
    pub fwmark: u32,

    /// The port of the device
    pub port: u16,

    /// The peers
    pub peers: Peers,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// `WireGuard` peer union
pub struct Peers {
    /// The number of peers
    pub num_peers: UnionField<u16>,

    /// The overall peer size
    pub peers_size: UnionField<u32>,

    /// The union field size as placeholder
    pub union_size: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// A `WireGuard` IP mask
pub struct WgIpMask {
    /// The network family
    pub family: i32,

    /// The network address
    pub addr: Addr,

    /// Classless Inter-Domain Routing
    pub cidr: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// A `WireGuard` network address
pub struct Addr {
    /// IP version 4
    pub ip4: UnionField<in_addr>,

    /// IP version 6
    pub ip6: UnionField<in6_addr>,

    /// The union field size as placeholder
    pub union_size: [u32; 4usize],
}

#[repr(C)]
#[derive(Clone, Copy)]
/// A `WireGuard` peer
pub struct WgPeer {
    /// The public key
    pub public_key: [u8; 32usize],

    /// Set flags for the peer
    pub flags: u32,

    /// The endpoint of the peer
    pub endpoint: WgEndpoint,

    /// Time of the last handshake
    pub last_handshake_time: timeval,

    /// Received bytes
    pub rx_bytes: u64,

    /// Sent bytes
    pub tx_bytes: u64,

    /// The persistent keep alive interval
    pub persistent_keepalive_interval: u16,

    /// The amount of IP masks
    pub num_ipmasks: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// A `WireGuard` endpoint type
pub struct WgEndpoint {
    /// The socket address
    pub addr: UnionField<sockaddr>,

    /// The IPv4 socket address
    pub addr4: UnionField<sockaddr_in>,

    /// The IPv6 socket address
    pub addr6: UnionField<sockaddr_in6>,

    /// The union field size as placeholder
    pub union_size: [u32; 7usize],
}
