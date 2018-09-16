/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

use failure::{Error, err_msg};
use interface::SharedPeer;
use treebitmap::{IpLookupTable, IpLookupTableOps};
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use ip_packet::IpPacket;

/// The `Router` struct is, as one might expect, the authority for the IP routing table.
pub struct Router {
    ip4_map: IpLookupTable<Ipv4Addr, SharedPeer>,
    ip6_map: IpLookupTable<Ipv6Addr, SharedPeer>,
}

impl Default for Router {
    fn default() -> Self {
        Self {
            ip4_map: IpLookupTable::new(),
            ip6_map: IpLookupTable::new(),
        }
    }
}

impl Router {
    pub fn add_allowed_ips(&mut self, allowed_ips: &[(IpAddr, u32)], peer: &SharedPeer) {
        for &(ip_addr, mask) in allowed_ips {
            self.add_allowed_ip(ip_addr, mask, peer.clone());
        }
    }

    pub fn add_allowed_ip(&mut self, addr: IpAddr, mask: u32, peer: SharedPeer) {
        match addr {
            IpAddr::V4(v4_addr) => { self.ip4_map.insert(v4_addr, mask, peer.clone()); },
            IpAddr::V6(v6_addr) => { self.ip6_map.insert(v6_addr, mask, peer); },
        }
    }

    pub fn remove_allowed_ips(&mut self, allowed_ips: &[(IpAddr, u32)]) {
        for &(ip_addr, mask) in allowed_ips {
            self.remove_allowed_ip(ip_addr, mask);
        }
    }

    pub fn remove_allowed_ip(&mut self, addr: IpAddr, mask: u32) {
        match addr {
            IpAddr::V4(v4_addr) => { let _ = self.ip4_map.remove(v4_addr, mask); },
            IpAddr::V6(v6_addr) => { let _ = self.ip6_map.remove(v6_addr, mask); },
        }
    }

    pub fn clear(&mut self) {
        self.ip4_map = IpLookupTable::new();
        self.ip6_map = IpLookupTable::new();
    }

    fn get_peer_from_ip(&self, ip: IpAddr) -> Option<SharedPeer> {
        match ip {
            IpAddr::V4(ip) => self.ip4_map.longest_match(ip).map(|(_, _, peer)| peer.clone()),
            IpAddr::V6(ip) => self.ip6_map.longest_match(ip).map(|(_, _, peer)| peer.clone())
        }
    }

    pub fn route_to_peer(&self, packet: &[u8]) -> Option<SharedPeer> {
        match IpPacket::new(packet) {
            Some(packet) => self.get_peer_from_ip(packet.destination()),
            _ => None
        }
    }

    pub fn validate_source(&self, packet: &[u8], peer: &SharedPeer) -> Result<(), Error> {
        let routed_peer = match IpPacket::new(packet) {
            Some(packet) => self.get_peer_from_ip(packet.source()),
            _ => None
        }.ok_or_else(|| err_msg("no peer found on route"))?;

        ensure!(&routed_peer == peer, "peer mismatch");
        Ok(())
    }
}
