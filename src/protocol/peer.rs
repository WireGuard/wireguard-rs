use anti_replay::AntiReplay;
use byteorder::{ByteOrder, BigEndian, LittleEndian};
use blake2_rfc::blake2s::{Blake2s, blake2s};
use consts::{TRANSPORT_OVERHEAD, TRANSPORT_HEADER_SIZE};
use failure::{Error, SyncFailure};
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
use tai64n::TAI64N;
use time;
use rand::{self, Rng};
use snow;
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
    pub last_handshake_tai64n: Option<TAI64N>,
}

impl PartialEq for Peer {
    fn eq(&self, other: &Peer) -> bool {
        self.info.pub_key == other.info.pub_key
    }

    fn ne(&self, other: &Peer) -> bool {
        self.info.pub_key != other.info.pub_key
    }
}

pub struct Session {
    pub noise: snow::Session,
    pub our_index: u32,
    pub their_index: u32,
    pub anti_replay: AntiReplay,
}

impl Session {
    #[allow(dead_code)]
    pub fn with_their_index(session: snow::Session, their_index: u32) -> Session {
        Session {
            noise: session,
            our_index: rand::thread_rng().gen::<u32>(),
            their_index,
            anti_replay: AntiReplay::default(),
        }
    }

    pub fn into_transport_mode(self) -> Session {
        Session {
            noise: self.noise.into_transport_mode().unwrap(),
            our_index: self.our_index,
            their_index: self.their_index,
            anti_replay: self.anti_replay,
        }
    }
}

impl From<snow::Session> for Session {
    fn from(session: snow::Session) -> Self {
        Session {
            noise: session,
            our_index: rand::thread_rng().gen::<u32>(),
            their_index: 0,
            anti_replay: AntiReplay::default(),
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

    pub fn ratchet_session(&mut self) -> Result<Option<Session>, Error> {
        let next = std::mem::replace(&mut self.sessions.next, None)
            .ok_or_else(|| format_err!("next session is missing"))?;
        let next = next.into_transport_mode();

        let current = std::mem::replace(&mut self.sessions.current, Some(next));
        let dead    = std::mem::replace(&mut self.sessions.past,    current);

        self.last_handshake = Some(SystemTime::now());
        Ok(dead)
    }

    pub fn handle_incoming_transport(&mut self, our_index: u32, nonce: u64, addr: SocketAddr, packet: &[u8]) -> Result<Vec<u8>, Error> {

        let session = self.sessions.current.as_mut().filter(|session| session.our_index == our_index)
            .or(self.sessions.past.as_mut().filter(|session| session.our_index == our_index))
            .ok_or_else(|| format_err!("couldn't find available session"))?;

        session.anti_replay.update(nonce)?;

        let mut raw_packet = vec![0u8; 1500];
        session.noise.set_receiving_nonce(nonce)
            .map_err(SyncFailure::new)?;
        let len = session.noise.read_message(packet, &mut raw_packet)
            .map_err(SyncFailure::new)?;

        self.rx_bytes += packet.len() as u64;
        self.info.endpoint = Some(addr); // update peer endpoint after successful authentication

        raw_packet.truncate(len);
        Ok(raw_packet)
    }

    pub fn handle_outgoing_transport(&mut self, packet: &[u8]) -> Result<(SocketAddr, Vec<u8>), Error> {
        let session = self.sessions.current.as_mut().ok_or_else(|| format_err!("no current noise session"))?;
        let endpoint = self.info.endpoint.ok_or_else(|| format_err!("no known peer endpoint"))?;

        let mut out_packet = vec![0u8; packet.len() + TRANSPORT_OVERHEAD];
        out_packet[0] = 4;
        LittleEndian::write_u32(&mut out_packet[4..], session.their_index);
        LittleEndian::write_u64(&mut out_packet[8..], session.noise.sending_nonce().map_err(SyncFailure::new)?);
        let len = session.noise.write_message(packet, &mut out_packet[16..])
            .map_err(SyncFailure::new)?;
        self.tx_bytes += len as u64;
        out_packet.truncate(TRANSPORT_HEADER_SIZE + len);
        Ok((endpoint, out_packet))
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

    pub fn get_handshake_packet(&mut self) -> Result<Vec<u8>, Error> {
        let tai64n = TAI64N::now();
        let mut initiation_packet = vec![0; 148];
        initiation_packet[0] = 1; /* Type: Initiation */

        let next = self.sessions.next.as_mut().ok_or_else(|| format_err!("missing next session"))?;
        LittleEndian::write_u32(&mut initiation_packet[4..], next.our_index);
        next.noise.write_message(&*tai64n, &mut initiation_packet[8..]).map_err(SyncFailure::new)?;

        let mut mac_key_input = [0; 40];
        memcpy(&mut mac_key_input, b"mac1----");
        memcpy(&mut mac_key_input[8..], &self.info.pub_key);
        let mac_key = blake2s(32, &[], &mac_key_input);
        let mac = blake2s(16, mac_key.as_bytes(), &initiation_packet[0..116]);
        memcpy(&mut initiation_packet[116..], mac.as_bytes());

        Ok(initiation_packet)
    }

    /// Takes a new handshake packet (type 0x01), updates the internal peer state,
    /// and generates a response.
    ///
    /// Returns: the response packet (type 0x02), and an optional dead session index that was removed.
    pub fn process_incoming_handshake(&mut self, addr: SocketAddr, their_index: u32, timestamp: TAI64N, mut noise: snow::Session)
            -> Result<(Vec<u8>, u32, Option<u32>), Error> {

        if let Some(ref last_tai64n) = self.last_handshake_tai64n {
            ensure!(&timestamp > last_tai64n, "handshake timestamp earlier than last handshake's timestamp");
        }

        // TODO: hacked up API until it's officially supported in snow.
        match noise {
            snow::Session::Handshake(ref mut handshake_state) => {
                handshake_state.set_psk(2, &self.info.psk.unwrap_or_else(|| [0u8; 32]));
            },
            _ => unreachable!()
        }

        let mut next_session = Session::with_their_index(noise, their_index);
        let next_index = next_session.our_index;
        let response_packet = self.get_response_packet(&mut next_session)?;
        self.set_next_session(next_session);

        let dead_index = self.ratchet_session()?.map(|session| session.our_index);

        self.info.endpoint = Some(addr); // update peer endpoint after successful authentication
        self.last_handshake_tai64n = Some(timestamp);

        Ok((response_packet, next_index, dead_index))
    }

    fn get_response_packet(&mut self, next_session: &mut Session) -> Result<Vec<u8>, Error> {
        let mut packet = vec![0; 76];
        packet[0] = 2; /* Type: Response */
        LittleEndian::write_u32(&mut packet[4..], next_session.our_index);
        LittleEndian::write_u32(&mut packet[8..], next_session.their_index);
        next_session.noise.write_message(&[], &mut packet[12..]).map_err(SyncFailure::new)?;
        let mut mac_key_input = [0; 40];
        memcpy(&mut mac_key_input, b"mac1----");
        memcpy(&mut mac_key_input[8..], &self.info.pub_key);
        let mac_key = blake2s(32, &[], &mac_key_input);
        let mac = blake2s(16, mac_key.as_bytes(), &packet[0..44]);
        memcpy(&mut packet[44..], mac.as_bytes());

        Ok(packet)
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
