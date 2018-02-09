use failure::Error;
use interface::{SharedPeer, UtunPacket};
use protocol::Peer;
use treebitmap::{IpLookupTable, IpLookupTableOps};
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr, SocketAddr};
use ip_packet::IpPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;

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

    fn get_peer_from_ip(&self, ip: IpAddr) -> Option<SharedPeer> {
        match ip {
            IpAddr::V4(ip) => self.ip4_map.longest_match(ip).map(|(_, _, peer)| peer.clone()),
            IpAddr::V6(ip) => self.ip6_map.longest_match(ip).map(|(_, _, peer)| peer.clone())
        }
    }

    pub fn route_to_peer(&self, packet: &[u8]) -> Option<SharedPeer> {
        match IpPacket::new(&packet) {
            Some(packet) => self.get_peer_from_ip(packet.get_destination()),
            _ => None
        }
    }

    pub fn validate_source(&self, packet: &[u8], peer: &SharedPeer) -> Result<(), Error> {
        let routed_peer = match IpPacket::new(&packet) {
            Some(packet) => self.get_peer_from_ip(packet.get_source()),
            _ => None
        }.ok_or_else(|| format_err!("no peer found on route"))?;

        ensure!(&routed_peer == peer, "peer mismatch");
        Ok(())
    }
}