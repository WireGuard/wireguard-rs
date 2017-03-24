// Copyright 2017 Guanhao Yin <sopium@mysterious.site>

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

extern crate pnet;

use self::pnet::packet::ipv4::Ipv4Packet;
use self::pnet::packet::ipv6::Ipv6Packet;
use std::net::IpAddr;

// IP packet parsing.

/// Parses IPv4/v6 packet, returns total length, source, destination.
pub fn parse_ip_packet(packet: &[u8]) -> Result<(u16, IpAddr, IpAddr), ()> {
    if packet.len() < 20 {
        return Err(());
    }

    let v = packet[0] >> 4;

    if v == 4 {
        // IPv4.
        let p = Ipv4Packet::new(packet).ok_or(())?;
        let len = p.get_total_length();
        let src = p.get_source();
        let dst = p.get_destination();
        Ok((len, IpAddr::V4(src), IpAddr::V4(dst)))
    } else if v == 6 {
        // IPv6.
        let p = Ipv6Packet::new(packet).ok_or(())?;
        let len = p.get_payload_length() + 40;
        let src = p.get_source();
        let dst = p.get_destination();
        Ok((len, IpAddr::V6(src), IpAddr::V6(dst)))
    } else {
        Err(())
    }
}
