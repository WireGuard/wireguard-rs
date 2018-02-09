use failure::Error;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr, SocketAddr};

pub enum IpPacket<'a> {
    V4(Ipv4Packet<'a>),
    V6(Ipv6Packet<'a>),
}

impl<'a> IpPacket<'a> {
    pub fn new(packet: &'a [u8]) -> Option<Self> {
        match packet[0] >> 4 {
            4 => Ipv4Packet::new(&packet).map(|packet| IpPacket::V4(packet)),
            6 => Ipv6Packet::new(&packet).map(|packet| IpPacket::V6(packet)),
            _ => None
        }
    }

    pub fn get_source(&self) -> IpAddr {
        match *self {
            IpPacket::V4(ref packet) => packet.get_source().into(),
            IpPacket::V6(ref packet) => packet.get_source().into(),
        }
    }

    pub fn get_destination(&self) -> IpAddr {
        match *self {
            IpPacket::V4(ref packet) => packet.get_destination().into(),
            IpPacket::V6(ref packet) => packet.get_destination().into(),
        }
    }
}
