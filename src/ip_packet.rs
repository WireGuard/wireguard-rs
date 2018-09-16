/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

use rips_packets::ipv4::Ipv4Packet;
use rips_packets::ipv6::Ipv6Packet;
use std::net::IpAddr;

pub enum IpPacket<'a> {
    V4(Ipv4Packet<'a>),
    V6(Ipv6Packet<'a>),
}

impl<'a> IpPacket<'a> {
    pub fn new(packet: &'a [u8]) -> Option<Self> {
        match packet.get(0).map(|byte| *byte >> 4) {
            Some(4) => Ipv4Packet::new(packet).map(IpPacket::V4),
            Some(6) => Ipv6Packet::new(packet).map(IpPacket::V6),
            _ => None
        }
    }

    pub fn source(&self) -> IpAddr {
        match *self {
            IpPacket::V4(ref packet) => packet.source().into(),
            IpPacket::V6(ref packet) => packet.source().into(),
        }
    }

    pub fn destination(&self) -> IpAddr {
        match *self {
            IpPacket::V4(ref packet) => packet.destination().into(),
            IpPacket::V6(ref packet) => packet.destination().into(),
        }
    }

    pub fn length(&self) -> u16 {
        match *self {
            IpPacket::V4(ref packet) => packet.total_length(),
            IpPacket::V6(ref packet) => 40 + packet.payload_length(),
        }

    }
}
