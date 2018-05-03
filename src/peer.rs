use anti_replay::AntiReplay;
use byteorder::{ByteOrder, LittleEndian};
use consts::{TRANSPORT_OVERHEAD, TRANSPORT_HEADER_SIZE, REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME,
             REKEY_AFTER_TIME_RECV, REJECT_AFTER_TIME, REJECT_AFTER_MESSAGES, PADDING_MULTIPLE,
             MAX_QUEUED_PACKETS};
use cookie;
use failure::{Error, err_msg};
use interface::UtunPacket;
use ip_packet::IpPacket;
use noise;
use message::{Initiation, Response, CookieReply, Transport};
use std::{self, mem};
use std::collections::VecDeque;
use std::fmt::{self, Debug, Display, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};
use hex;
use timestamp::{Tai64n, Timestamp};
use snow;
use types::PeerInfo;
use udp::Endpoint;

pub struct Peer {
    pub info                  : PeerInfo,
    pub sessions              : Sessions,
    pub timers                : Timers,
    pub tx_bytes              : u64,
    pub rx_bytes              : u64,
    pub last_handshake_tai64n : Option<Tai64n>,
    pub outgoing_queue        : VecDeque<UtunPacket>,
    pub cookie                : cookie::Generator,
}

impl PartialEq for Peer {
    fn eq(&self, other: &Peer) -> bool {
        self.info.pub_key == other.info.pub_key
    }
}

#[derive(Debug, PartialEq)]
pub enum SessionType {
    Past, Current, Next
}

#[derive(Debug, PartialEq)]
pub enum SessionTransition {
    NoTransition, Transition(Option<u32>)
}

#[derive(Default)]
pub struct Timers {
    pub data_sent               : Timestamp,
    pub data_received           : Timestamp,
    pub authenticated_received  : Timestamp,
    pub authenticated_traversed : Timestamp,
    pub egress_queued           : Timestamp,
    pub handshake_completed     : Timestamp,
    pub handshake_initialized   : Timestamp,
}

pub struct Session {
    pub noise          : snow::Session,
    pub our_index      : u32,
    pub their_index    : u32,
    pub anti_replay    : AntiReplay,
    pub birthday       : Timestamp,
    pub last_sent      : Timestamp,
    pub last_received  : Timestamp,
    pub keepalive_sent : bool,
}

impl Session {
    pub fn new(noise: snow::Session, our_index: u32) -> Session {
        Session {
            noise,
            our_index,
            their_index    : 0,
            anti_replay    : AntiReplay::default(),
            last_sent      : Timestamp::default(),
            last_received  : Timestamp::default(),
            birthday       : Timestamp::default(),
            keepalive_sent : false,
        }
    }

    pub fn with_their_index(noise: snow::Session, our_index: u32, their_index: u32) -> Session {
        Session {
            noise,
            our_index,
            their_index,
            anti_replay    : AntiReplay::default(),
            last_sent      : Timestamp::default(),
            last_received  : Timestamp::default(),
            birthday       : Timestamp::default(),
            keepalive_sent : false,
        }
    }

    pub fn into_transport_mode(self) -> Result<Session, Error> {
        Ok(Session {
            noise          : self.noise.into_transport_mode()?,
            our_index      : self.our_index,
            their_index    : self.their_index,
            anti_replay    : self.anti_replay,
            last_sent      : self.last_sent,
            last_received  : self.last_received,
            keepalive_sent : self.keepalive_sent,
            birthday       : self.birthday,
        })
    }
}

pub struct IncompleteIncomingHandshake {
    their_index : u32,
    timestamp   : Tai64n,
    noise       : snow::Session,
}

impl IncompleteIncomingHandshake {
    pub fn their_pubkey(&self) -> &[u8] {
        self.noise.get_remote_static().expect("must have remote static key")
    }
}

#[derive(Default)]
pub struct Sessions {
    pub past    : Option<Session>,
    pub current : Option<Session>,
    pub next    : Option<Session>,
}

impl Sessions {
    /// Remove all stored sessions from memory, returning all of our indices that were stored
    /// in order to clear out caches/maps.
    pub fn wipe(&mut self) -> Vec<u32> {
        let indices = vec![mem::replace(&mut self.past,    None),
                           mem::replace(&mut self.current, None),
                           mem::replace(&mut self.next,    None)];

        indices.into_iter().filter_map(|sesh| sesh.map(|s| s.our_index)).collect()
    }
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

impl Peer {
    pub fn new(info: PeerInfo) -> Peer {
        let cookie = cookie::Generator::new(&info.pub_key);
        Peer {
            info,
            cookie,
            sessions              : Default::default(),
            timers                : Default::default(),
            tx_bytes              : Default::default(),
            rx_bytes              : Default::default(),
            last_handshake_tai64n : Default::default(),
            outgoing_queue        : Default::default(),
        }
    }

    pub fn find_session(&mut self, our_index: u32) -> Option<(&mut Session, SessionType)> {
        let sessions = &mut self.sessions;

        match (&mut sessions.next, &mut sessions.current, &mut sessions.past) {
            (&mut Some(ref mut s), _, _) if s.our_index == our_index => Some((s, SessionType::Next)),
            (_, &mut Some(ref mut s), _) if s.our_index == our_index => Some((s, SessionType::Current)),
            (_, _, &mut Some(ref mut s)) if s.our_index == our_index => Some((s, SessionType::Past)),
            _                                                        => None
        }
    }

    pub fn queue_egress(&mut self, packet: UtunPacket) {
        if self.outgoing_queue.len() < MAX_QUEUED_PACKETS {
            self.outgoing_queue.push_back(packet);
            self.timers.egress_queued = Timestamp::now();
        } else {
            debug!("dropping pending egress packet because the queue is full");
        }
    }

    pub fn needs_new_handshake(&self, sending: bool) -> bool {
        if self.sessions.next.is_some() {
            return false;
        }
        if self.sessions.current.is_none() {
            debug!("needs new handshake: no current session");
            return true;
        }
        if sending && self.timers.handshake_completed.elapsed() > *REKEY_AFTER_TIME {
            debug!("needs new handshake: sending after REKEY_AFTER_TIME");
            return true;
        }
        if !sending && self.timers.handshake_completed.elapsed() > *REKEY_AFTER_TIME_RECV {
            debug!("needs new handshake: receiving after RECV_REKEY_AFTER_TIME");
            return true;
        }
        if let Some(ref session) = self.sessions.current {
            if session.noise.sending_nonce().unwrap() >= REKEY_AFTER_MESSAGES {
                debug!("needs new handshake: nonce >= REKEY_AFTER_MESSAGES");
                return true;
            }
        }
        false
    }

    pub fn ready_for_transport(&self) -> bool {
        self.sessions.current.is_some()
    }

    pub fn get_mapped_indices(&self) -> Vec<u32> {
        let mut indices = Vec::with_capacity(3);
        if let Some(ref session) = self.sessions.past    { indices.push(session.our_index); }
        if let Some(ref session) = self.sessions.current { indices.push(session.our_index); }
        if let Some(ref session) = self.sessions.next    { indices.push(session.our_index); }
        indices
    }

    pub fn initiate_new_session(&mut self, private_key: &[u8], index: u32) -> Result<(Endpoint, Vec<u8>, Option<u32>), Error> {
        let     noise    = noise::build_initiator(private_key, &self.info.pub_key, &self.info.psk)?;
        let mut session  = Session::new(noise, index);
        let     endpoint = self.info.endpoint.ok_or_else(|| err_msg("no known peer endpoint"))?;
        let mut packet   = vec![0; 148];

        let tai64n = Tai64n::now();
        packet[0] = 1;

        LittleEndian::write_u32(&mut packet[4..], session.our_index);
        session.noise.write_message(&*tai64n, &mut packet[8..])?;
        let (mac1, mac2) = self.cookie.build_macs(&packet[..116]);
        packet[116..132].copy_from_slice(mac1.as_bytes());
        if let Some(mac2) = mac2 {
            packet[132..].copy_from_slice(mac2.as_bytes());
        }

        let old_next = mem::replace(&mut self.sessions.next, Some(session));
        let dead_index = if old_next.is_some() {
            mem::replace(&mut self.sessions.past, old_next).map(|session| session.our_index)
        } else {
            None
        };

        Ok((endpoint, packet, dead_index))
    }

    pub fn process_incoming_handshake(private_key: &[u8], packet: &Initiation) -> Result<IncompleteIncomingHandshake, Error> {
        let mut timestamp = [0u8; 12];
        let mut noise     = noise::build_responder(private_key)?;

        let len = noise.read_message(packet.noise_bytes(), &mut timestamp)?;
        ensure!(len == 12, "incorrect handshake payload length");
        let timestamp = timestamp.into();

        Ok(IncompleteIncomingHandshake { their_index: packet.their_index(), timestamp, noise })
    }

    /// Takes a new handshake packet (type 0x01), updates the internal peer state,
    /// and generates a response.
    ///
    /// Returns: the response packet (type 0x02), and an optional dead session index that was removed.
    pub fn complete_incoming_handshake(&mut self, addr: Endpoint, index: u32, incomplete: IncompleteIncomingHandshake) -> Result<(Vec<u8>, Option<u32>), Error> {
        let IncompleteIncomingHandshake { timestamp, their_index, mut noise } = incomplete;

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

        let mut next_session  = Session::with_their_index(noise, index, their_index);
        next_session.birthday = Timestamp::now();

        let response_packet = self.get_response_packet(&mut next_session)?;
        let old_next        = mem::replace(&mut self.sessions.next, Some(next_session.into_transport_mode()?));

        let dead_index = if old_next.is_some() {
            mem::replace(&mut self.sessions.past, old_next).map(|session| session.our_index)
        } else {
            None
        };

        self.info.endpoint         = Some(addr);
        self.last_handshake_tai64n = Some(timestamp);

        Ok((response_packet, dead_index))
    }

    fn get_response_packet(&mut self, next_session: &mut Session) -> Result<Vec<u8>, Error> {
        let mut packet = vec![0; 92];
        packet[0] = 2;
        LittleEndian::write_u32(&mut packet[4..], next_session.our_index);
        LittleEndian::write_u32(&mut packet[8..], next_session.their_index);
        next_session.noise.write_message(&[], &mut packet[12..])?;
        let (mac1, mac2) = self.cookie.build_macs(&packet[..60]);
        packet[60..76].copy_from_slice(mac1.as_bytes());
        if let Some(mac2) = mac2 {
            packet[76..].copy_from_slice(mac2.as_bytes());
        }

        Ok(packet)
    }

    pub fn consume_cookie_reply(&mut self, reply: &CookieReply) -> Result<(), Error> {
        self.cookie.consume_reply(reply)
    }

    pub fn process_incoming_handshake_response(&mut self, addr: Endpoint, packet: &Response) -> Result<Option<u32>, Error> {
        let mut session = mem::replace(&mut self.sessions.next, None).ok_or_else(|| err_msg("no next session"))?;
        let     _       = session.noise.read_message(packet.noise_bytes(), &mut [])?;

        session             = session.into_transport_mode()?;
        session.their_index = packet.their_index();
        session.birthday    = Timestamp::now();

        self.timers.handshake_completed = Timestamp::now();
        self.info.endpoint              = Some(addr);

        let current = mem::replace(&mut self.sessions.current, Some(session));
        let dead    = mem::replace(&mut self.sessions.past,    current);

        Ok(dead.map(|session| session.our_index))
    }

    pub fn handle_incoming_transport(&mut self, addr: Endpoint, packet: &Transport)
        -> Result<(Vec<u8>, SessionTransition), Error> {

        let mut raw_packet = vec![0u8; packet.len()];
        let     nonce      = packet.nonce();

        let session_type = {
            let (session, session_type) = self.find_session(packet.our_index()).ok_or_else(|| err_msg("no session with index"))?;
            ensure!(session.noise.is_handshake_finished(),              "session is not ready for transport packets");
            ensure!(nonce                      < REJECT_AFTER_MESSAGES, "exceeded REJECT-AFTER-MESSAGES");
            ensure!(session.birthday.elapsed() < *REJECT_AFTER_TIME,    "exceeded REJECT-AFTER-TIME");

            session.anti_replay.update(nonce)?;
            session.noise.set_receiving_nonce(nonce)?;
            let len = session.noise.read_message(packet.payload(), &mut raw_packet)?;
            if len > 0 {
                let len = IpPacket::new(&raw_packet[..len])
                    .ok_or_else(||format_err!("invalid IP packet (len {})", len))?
                    .length();
                raw_packet.truncate(len as usize);
            } else {
                raw_packet.truncate(0);
            }

            session.last_received  = Timestamp::now();
            session.keepalive_sent = false; // reset passive keepalive token since received a valid ingress transport

            session_type
        };

        let transition = if session_type == SessionType::Next {
            debug!("moving 'next' session to current after receiving first transport packet");
            let next    = std::mem::replace(&mut self.sessions.next, None);
            let current = std::mem::replace(&mut self.sessions.current, next);
            let dead    = std::mem::replace(&mut self.sessions.past, current);

            self.timers.handshake_completed = Timestamp::now();

            SessionTransition::Transition(dead.map(|session| session.our_index))
        } else {
            SessionTransition::NoTransition
        };

        self.rx_bytes     += packet.len() as u64;
        self.info.endpoint = Some(addr); // update peer endpoint after successful authentication

        Ok((raw_packet, transition))
    }

    pub fn handle_outgoing_transport(&mut self, packet: &[u8]) -> Result<(Endpoint, Vec<u8>), Error> {
        let session        = self.sessions.current.as_mut().ok_or_else(|| err_msg("no current noise session"))?;
        let endpoint       = self.info.endpoint.ok_or_else(|| err_msg("no known peer endpoint"))?;
        let padding        = PADDING_MULTIPLE - (packet.len() % PADDING_MULTIPLE);
        let padded_len     = packet.len() + padding;
        let mut out_packet = vec![0u8; padded_len + TRANSPORT_OVERHEAD];

        let nonce = session.noise.sending_nonce()?;
        ensure!(nonce                      < REJECT_AFTER_MESSAGES, "exceeded REJECT-AFTER-MESSAGES");
        ensure!(session.birthday.elapsed() < *REJECT_AFTER_TIME,    "exceeded REJECT-AFTER-TIME");

        out_packet[0] = 4;
        LittleEndian::write_u32(&mut out_packet[4..], session.their_index);
        LittleEndian::write_u64(&mut out_packet[8..], nonce);
        let padded_packet = &[packet, &vec![0u8; padding]].concat();
        let len = session.noise.write_message(padded_packet, &mut out_packet[16..])?;
        self.tx_bytes += len as u64;
        session.last_sent = Timestamp::now();
        out_packet.truncate(TRANSPORT_HEADER_SIZE + len);
        Ok((endpoint, out_packet))
    }

    pub fn to_config_string(&self) -> String {
        let mut s = format!("public_key={}\n", hex::encode(&self.info.pub_key));
        if let Some(ref psk) = self.info.psk {
            s.push_str(&format!("preshared_key={}\n", hex::encode(psk)));
        }
        if let Some(ref endpoint) = self.info.endpoint {
            s.push_str(&format!("endpoint={}:{}\n", endpoint.ip().to_string(),endpoint.port()));
        }
        if let Some(keepalive) = self.info.keepalive {
            s.push_str(&format!("persistent_keepalive_interval={}\n",keepalive));
        }
        for &(ip, cidr) in &self.info.allowed_ips {
            s.push_str(&format!("allowed_ip={}/{}\n", ip, cidr));
        }
        s.push_str(&format!("tx_bytes={}\nrx_bytes={}\n", self.tx_bytes, self.rx_bytes));

        if self.timers.handshake_completed.is_set() {
            if let Ok(time) = (SystemTime::now() - self.timers.handshake_completed.elapsed()).duration_since(UNIX_EPOCH) {
                s.push_str(&format!("last_handshake_time_sec={}\nlast_handshake_time_nsec={}\n",
                                    time.as_secs(), time.subsec_nanos()));
            } else {
                warn!("SystemTime Duration error");
            }
        }
        s
    }
}
