use interface::{SharedPeer, UtunPacket};
use treebitmap::{IpLookupTable, IpLookupTableOps};
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr, SocketAddr};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};

/// The `Router` struct is, as one might expect, the authority for the IP routing table.
pub struct Router {
    ip4_map: IpLookupTable<Ipv4Addr, SharedPeer>,
    ip6_map: IpLookupTable<Ipv6Addr, SharedPeer>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            ip4_map: IpLookupTable::new(),
            ip6_map: IpLookupTable::new(),
        }
    }

    pub fn add_allowed_ips(&mut self, allowed_ips: &[(IpAddr, u32)], peer: SharedPeer) {
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

    pub fn route_to_peer(&self, packet: &UtunPacket) -> Option<SharedPeer> {
        match packet {
            &UtunPacket::Inet4(ref packet) => {
                let destination = Ipv4Packet::new(&packet).unwrap().get_destination();
                self.ip4_map.longest_match(destination).map(|(_, _, peer)| peer.clone())
            },
            &UtunPacket::Inet6(ref packet) => {
                let destination = Ipv6Packet::new(&packet).unwrap().get_destination();
                self.ip6_map.longest_match(destination).map(|(_, _, peer)| peer.clone())
            }
        }
    }
}