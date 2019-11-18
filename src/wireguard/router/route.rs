use super::super::{bind, tun, Endpoint};
use super::device::DeviceInner;
use super::ip::*;
use super::peer::PeerInner;
use super::types::Callbacks;

use log::trace;
use zerocopy::LayoutVerified;

use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

#[inline(always)]
pub fn get_route<E: Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>>(
    device: &Arc<DeviceInner<E, C, T, B>>,
    packet: &[u8],
) -> Option<Arc<PeerInner<E, C, T, B>>> {
    match packet.get(0)? >> 4 {
        VERSION_IP4 => {
            // check length and cast to IPv4 header
            let (header, _): (LayoutVerified<&[u8], IPv4Header>, _) =
                LayoutVerified::new_from_prefix(packet)?;

            log::trace!(
                "Router, get route for IPv4 destination: {:?}",
                Ipv4Addr::from(header.f_destination)
            );

            // check IPv4 source address
            device
                .ipv4
                .read()
                .longest_match(Ipv4Addr::from(header.f_destination))
                .and_then(|(_, _, p)| Some(p.clone()))
        }
        VERSION_IP6 => {
            // check length and cast to IPv6 header
            let (header, _): (LayoutVerified<&[u8], IPv6Header>, _) =
                LayoutVerified::new_from_prefix(packet)?;

            log::trace!(
                "Router, get route for IPv6 destination: {:?}",
                Ipv6Addr::from(header.f_destination)
            );

            // check IPv6 source address
            device
                .ipv6
                .read()
                .longest_match(Ipv6Addr::from(header.f_destination))
                .and_then(|(_, _, p)| Some(p.clone()))
        }
        _ => None,
    }
}

#[inline(always)]
pub fn check_route<E: Endpoint, C: Callbacks, T: tun::Writer, B: bind::Writer<E>>(
    device: &Arc<DeviceInner<E, C, T, B>>,
    peer: &Arc<PeerInner<E, C, T, B>>,
    packet: &[u8],
) -> Option<usize> {
    match packet.get(0)? >> 4 {
        VERSION_IP4 => {
            // check length and cast to IPv4 header
            let (header, _): (LayoutVerified<&[u8], IPv4Header>, _) =
                LayoutVerified::new_from_prefix(packet)?;

            log::trace!(
                "Router, check route for IPv4 source: {:?}",
                Ipv4Addr::from(header.f_source)
            );

            // check IPv4 source address
            device
                .ipv4
                .read()
                .longest_match(Ipv4Addr::from(header.f_source))
                .and_then(|(_, _, p)| {
                    if Arc::ptr_eq(p, peer) {
                        Some(header.f_total_len.get() as usize)
                    } else {
                        None
                    }
                })
        }
        VERSION_IP6 => {
            // check length and cast to IPv6 header
            let (header, _): (LayoutVerified<&[u8], IPv6Header>, _) =
                LayoutVerified::new_from_prefix(packet)?;

            log::trace!(
                "Router, check route for IPv6 source: {:?}",
                Ipv6Addr::from(header.f_source)
            );

            // check IPv6 source address
            device
                .ipv6
                .read()
                .longest_match(Ipv6Addr::from(header.f_source))
                .and_then(|(_, _, p)| {
                    if Arc::ptr_eq(p, peer) {
                        Some(header.f_len.get() as usize + mem::size_of::<IPv6Header>())
                    } else {
                        None
                    }
                })
        }
        _ => None,
    }
}
