// Copyright 2017 Sascha Grunert, Guanhao Yin <sopium@mysterious.site>

// This file is part of WireGuard.rs.

// WireGuard.rs is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// WireGuard.rs is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with WireGuard.rs.  If not, see <https://www.gnu.org/licenses/>.


//! Mapping to the `WireGuard` user API

use std::convert::{AsMut, AsRef};
use std::fmt::{Debug, Result, Formatter};
use std::marker::PhantomData;
use std::mem::transmute;
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use libc::{in_addr, in6_addr, sockaddr, sockaddr_in, sockaddr_in6, timeval, AF_INET, AF_INET6};
use nix::sys::socket as nix;

const IFNAMSIZ: usize = 16;
const WG_KEY_LEN: usize = 32;

#[repr(C)]
#[derive(Clone)]
/// Represents a union field
pub struct UnionField<T>(PhantomData<T>);

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

// Conversion between uapi/libc types <-> Rust std types.

/// Convert `SystemTime` to `struct timeval`.
pub fn system_time_to_timeval(t: &SystemTime) -> timeval {
    let d = t.duration_since(UNIX_EPOCH).unwrap();
    timeval {
        tv_sec: d.as_secs() as i64,
        tv_usec: (d.subsec_nanos() / 1000) as i64,
    }
}

/// Convert `IpAddr` to `(family, Addr)`.
pub fn ip_addr_to_addr(a: &IpAddr) -> (i32, Addr) {
    match *a {
        IpAddr::V4(ref a) => {
            let mut out: Addr = unsafe_zeroed();
            *out.ip4.as_mut() = nix::Ipv4Addr::from_std(a).0;
            (AF_INET, out)
        },
        IpAddr::V6(ref a) => {
            let mut out: Addr = unsafe_zeroed();
            *out.ip6.as_mut() = nix::Ipv6Addr::from_std(a).0;
            (AF_INET6, out)
        }
    }
}

/// Convert `(family, Addr)` to `IpAddr`.
pub fn addr_to_ip_addr(family: i32, a: &Addr) -> IpAddr {
    match family {
        AF_INET => IpAddr::V4(nix::Ipv4Addr(*a.ip4.as_ref()).to_std()),
        AF_INET6 => IpAddr::V6(nix::Ipv6Addr(*a.ip6.as_ref()).to_std()),
        f => panic!("Unknown addr family {}", f),
    }
}

/// Convert `SocketAddr` to `WgEndpoint`.
pub fn socket_addr_to_wg_endpoint(a: &SocketAddr) -> WgEndpoint {
    let mut out: WgEndpoint = unsafe_zeroed();

    match nix::InetAddr::from_std(a) {
        nix::InetAddr::V4(a) => *out.addr4.as_mut() = a,
        nix::InetAddr::V6(a) => *out.addr6.as_mut() = a,
    }

    out
}

/// Convert `WgEndpoint` to `SocketAddr`.
pub fn wg_endpoint_to_socket_addr(e: &WgEndpoint) -> SocketAddr {
    match e.addr.as_ref().sa_family as i32 {
        AF_INET => {
            nix::InetAddr::V4(*e.addr4.as_ref()).to_std()
        },
        AF_INET6 => {
            nix::InetAddr::V6(*e.addr6.as_ref()).to_std()
        },
        f => panic!("Unknown addr family {}", f),
    }
}

fn unsafe_zeroed<T>() -> T {
    unsafe { ::std::mem::zeroed() }
}
