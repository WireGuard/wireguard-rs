use byteorder::{ByteOrder, BigEndian, LittleEndian};
use blake2_rfc::blake2s::{Blake2s, blake2s};
use snow::{self, NoiseBuilder};
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::icmp::{self, MutableIcmpPacket, IcmpTypes, echo_reply, echo_request};
use std::{self, io};
use std::fmt::{self, Debug, Display, Formatter};
use std::net::{Ipv4Addr, IpAddr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use std::thread::JoinHandle;
use base64;
use hex;
use time;
use rand::{self, Rng};
use types::PeerInfo;

use futures::{self, Future};
use tokio_core::reactor::Handle;
use tokio_core::net::{UdpSocket, UdpCodec};

#[derive(Default)]
pub struct Peer {
    pub info: PeerInfo,
    pub sessions: Sessions,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_handshake: Option<SystemTime>,
}

pub struct Session {
    pub noise: snow::Session,
    pub our_index: u32,
    pub their_index: u32,
}

impl Session {
    #[allow(dead_code)]
    pub fn with_their_index(session: snow::Session, their_index: u32) -> Session {
        Session {
            noise: session,
            our_index: rand::thread_rng().gen::<u32>(),
            their_index,
        }
    }

    pub fn into_transport_mode(self) -> Session {
        Session {
            noise: self.noise.into_transport_mode().unwrap(),
            our_index: self.our_index,
            their_index: self.their_index,
        }
    }
}

impl From<snow::Session> for Session {
    fn from(session: snow::Session) -> Self {
        Session {
            noise: session,
            our_index: rand::thread_rng().gen::<u32>(),
            their_index: 0,
        }
    }
}

#[derive(Default)]
pub struct Sessions {
    pub past: Option<Session>,
    pub current: Option<Session>,
    pub next: Option<Session>,
}

impl Display for Peer {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Peer({})", self.info)
    }
}

impl Debug for Peer {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Peer( endpoint: {:?}, pubkey: [redacted], psk: [redacted] )", self.info.endpoint)
    }
}

fn memcpy(out: &mut [u8], data: &[u8]) {
    out[..data.len()].copy_from_slice(data);
}

impl Peer {
    pub fn new(info: PeerInfo) -> Peer {
        let mut peer = Peer::default();
        peer.info = info;
        peer
    }

    pub fn set_next_session(&mut self, session: Session) {
        let _ = std::mem::replace(&mut self.sessions.next, Some(session));
    }

    pub fn ratchet_session(&mut self) -> Result<(), ()> {
        let next = std::mem::replace(&mut self.sessions.next, None).ok_or(())?;
        let next = next.into_transport_mode();

        let current = std::mem::replace(&mut self.sessions.current, Some(next));
        let _       = std::mem::replace(&mut self.sessions.past,    current);

        self.last_handshake = Some(SystemTime::now());
        Ok(())
    }

    pub fn past_noise(&mut self) -> Option<&mut snow::Session> {
        if let Some(ref mut session) = self.sessions.past {
            Some(&mut session.noise)
        } else {
            None
        }
    }

    pub fn current_noise(&mut self) -> Option<&mut snow::Session> {
        if let Some(ref mut session) = self.sessions.current {
            Some(&mut session.noise)
        } else {
            None
        }
    }

    pub fn next_noise(&mut self) -> Option<&mut snow::Session> {
        if let Some(ref mut session) = self.sessions.next {
            Some(&mut session.noise)
        } else {
            None
        }
    }

    pub fn our_next_index(&self) -> Option<u32> {
        if let Some(ref session) = self.sessions.next {
            Some(session.our_index)
        } else {
            None
        }
    }

    pub fn our_current_index(&self) -> Option<u32> {
        if let Some(ref session) = self.sessions.current {
            Some(session.our_index)
        } else {
            None
        }
    }

    pub fn their_current_index(&self) -> Option<u32> {
        if let Some(ref session) = self.sessions.current {
            Some(session.their_index)
        } else {
            None
        }
    }

    pub fn get_handshake_packet(&mut self) -> Vec<u8> {
        let now = time::get_time();
        let mut tai64n = [0; 12];
        BigEndian::write_i64(&mut tai64n[0..], 4611686018427387914 + now.sec);
        BigEndian::write_i32(&mut tai64n[8..], now.nsec);
        let mut initiation_packet = vec![0; 148];
        initiation_packet[0] = 1; /* Type: Initiation */
        LittleEndian::write_u32(&mut initiation_packet[4..], self.our_next_index().unwrap());
        self.sessions.next.as_mut().unwrap().noise.write_message(&tai64n, &mut initiation_packet[8..]).unwrap();
        let mut mac_key_input = [0; 40];
        memcpy(&mut mac_key_input, b"mac1----");
        memcpy(&mut mac_key_input[8..], &self.info.pub_key);
        let mac_key = blake2s(32, &[], &mac_key_input);
        let mac = blake2s(16, mac_key.as_bytes(), &initiation_packet[0..116]);
        memcpy(&mut initiation_packet[116..], mac.as_bytes());

        initiation_packet
    }

    pub fn get_response_packet(&mut self) -> Vec<u8> {
        let mut packet = vec![0; 76];
        packet[0] = 2; /* Type: Response */
        let session = self.sessions.next.as_mut().unwrap();
        LittleEndian::write_u32(&mut packet[4..], session.our_index);
        LittleEndian::write_u32(&mut packet[8..], session.their_index);
        session.noise.write_message(&[], &mut packet[12..]).unwrap();
        let mut mac_key_input = [0; 40];
        memcpy(&mut mac_key_input, b"mac1----");
        memcpy(&mut mac_key_input[8..], &self.info.pub_key);
        let mac_key = blake2s(32, &[], &mac_key_input);
        let mac = blake2s(16, mac_key.as_bytes(), &packet[0..44]);
        memcpy(&mut packet[44..], mac.as_bytes());

        packet
    }

    pub fn to_config_string(&self) -> String {
        let mut s = format!("public_key={}\n", hex::encode(&self.info.pub_key));
        if let Some(ref psk) = self.info.psk {
            s.push_str(&format!("preshared_key={}\n", hex::encode(psk)));
        }
        if let Some(ref endpoint) = self.info.endpoint {
            s.push_str(&format!("endpoint={}:{}\n", endpoint.ip().to_string(),endpoint.port()));
        }
        s.push_str(&format!("tx_bytes={}\nrx_bytes={}\n", self.tx_bytes, self.rx_bytes));

        if let Some(ref last_handshake) = self.last_handshake {
            let time = last_handshake.duration_since(UNIX_EPOCH).unwrap();
            s.push_str(&format!("last_handshake_time_sec={}\nlast_handshake_time_nsec={}\n",
                                time.as_secs(), time.subsec_nanos()))
        }
        s
    }
}
