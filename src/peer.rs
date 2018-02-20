use anti_replay::AntiReplay;
use byteorder::{ByteOrder, LittleEndian};
use consts::{TRANSPORT_OVERHEAD, TRANSPORT_HEADER_SIZE, MAX_SEGMENT_SIZE, REJECT_AFTER_MESSAGES, PADDING_MULTIPLE};
use cookie;
use failure::{Error, err_msg};
use interface::UtunPacket;
use ip_packet::IpPacket;
use noise;
use std::{self, mem};
use std::collections::VecDeque;
use std::fmt::{self, Debug, Display, Formatter};
use std::net::SocketAddr;
use std::time::{SystemTime, Instant, UNIX_EPOCH};
use hex;
use tai64n::TAI64N;
use rand::{self, Rng};
use snow;
use types::PeerInfo;

#[derive(Default)]
pub struct Peer {
    pub info: PeerInfo,
    pub sessions: Sessions,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_sent_init: Option<Instant>,
    pub last_tun_queue: Option<Instant>,
    pub last_handshake: Option<Instant>,
    pub last_handshake_tai64n: Option<TAI64N>,
    pub outgoing_queue: VecDeque<UtunPacket>,
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

pub struct Session {
    pub noise: snow::Session,
    pub our_index: u32,
    pub their_index: u32,
    pub anti_replay: AntiReplay,
    pub last_sent: Option<Instant>,
    pub last_received: Option<Instant>,
}

impl Session {
    #[allow(dead_code)]
    pub fn with_their_index(session: snow::Session, their_index: u32) -> Session {
        Session {
            noise: session,
            our_index: rand::thread_rng().gen::<u32>(),
            their_index,
            anti_replay: AntiReplay::default(),
            last_sent: None,
            last_received: None,
        }
    }

    pub fn into_transport_mode(self) -> Session {
        Session {
            noise: self.noise.into_transport_mode().unwrap(),
            our_index: self.our_index,
            their_index: self.their_index,
            anti_replay: self.anti_replay,
            last_sent: self.last_sent,
            last_received: self.last_received,
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
            last_sent: None,
            last_received: None,
        }
    }
}

pub struct IncompleteIncomingHandshake {
    their_index: u32,
    timestamp: TAI64N,
    noise: snow::Session,
}

impl IncompleteIncomingHandshake {
    pub fn their_pubkey(&self) -> &[u8] {
        self.noise.get_remote_static().expect("must have remote static key")
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

impl Peer {
    pub fn new(info: PeerInfo) -> Peer {
        let mut peer = Peer::default();
        peer.info = info;
        peer
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
        self.outgoing_queue.push_back(packet);
        self.last_tun_queue = Some(Instant::now());
    }

    pub fn needs_new_handshake(&self) -> bool {
        self.sessions.current.is_none() && self.sessions.next.is_none()
    }

    pub fn ready_for_transport(&self) -> bool {
        self.sessions.current.is_some()
    }

    pub fn initiate_new_session(&mut self, private_key: &[u8]) -> Result<(SocketAddr, Vec<u8>, u32, Option<u32>), Error> {
        let     noise    = noise::build_initiator(private_key, &self.info.pub_key, &self.info.psk)?;
        let mut session  = Session::from(noise);
        let     endpoint = self.info.endpoint.ok_or_else(|| err_msg("no known peer endpoint"))?;
        let mut packet   = vec![0; 148];

        let tai64n = TAI64N::now();
        packet[0] = 1; /* Type: Initiation */

        LittleEndian::write_u32(&mut packet[4..], session.our_index);
        session.noise.write_message(&*tai64n, &mut packet[8..])?;
        {
            let (mac_in, mac_out) = packet.split_at_mut(116);
            cookie::build_mac1(&self.info.pub_key, mac_in, &mut mac_out[..16]);
        }

        let our_index  = session.our_index;
        let dead       = mem::replace(&mut self.sessions.next, Some(session));
        let dead_index = dead.map(|session| session.our_index);

        Ok((endpoint, packet, our_index, dead_index))
    }

    pub fn process_incoming_handshake(private_key: &[u8], packet: &[u8]) -> Result<IncompleteIncomingHandshake, Error> {
        let mut timestamp = [0u8; 12];
        let mut noise     = noise::build_responder(private_key)?;
        let their_index   = LittleEndian::read_u32(&packet[4..]);

        let len = noise.read_message(&packet[8..116], &mut timestamp)?;
        ensure!(len == 12, "incorrect handshake payload length");
        let timestamp = timestamp.into();

        Ok(IncompleteIncomingHandshake { their_index, timestamp, noise })
    }

    /// Takes a new handshake packet (type 0x01), updates the internal peer state,
    /// and generates a response.
    ///
    /// Returns: the response packet (type 0x02), and an optional dead session index that was removed.
    pub fn complete_incoming_handshake(&mut self, addr: SocketAddr, incomplete: IncompleteIncomingHandshake) -> Result<(Vec<u8>, u32), Error> {
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

        let mut next_session = Session::with_their_index(noise, their_index);
        let next_index = next_session.our_index;
        let response_packet = self.get_response_packet(&mut next_session)?;
        // TODO return and dispose of killed "next" session if exists
        let _ = mem::replace(&mut self.sessions.next, Some(next_session.into_transport_mode()));
        self.info.endpoint = Some(addr);
        self.last_handshake_tai64n = Some(timestamp);

        Ok((response_packet, next_index))
    }

    fn get_response_packet(&mut self, next_session: &mut Session) -> Result<Vec<u8>, Error> {
        let mut packet = vec![0; 92];
        packet[0] = 2;
        LittleEndian::write_u32(&mut packet[4..], next_session.our_index);
        LittleEndian::write_u32(&mut packet[8..], next_session.their_index);
        next_session.noise.write_message(&[], &mut packet[12..])?;

        {
            let (mac_in, mac_out) = packet.split_at_mut(60);
            cookie::build_mac1(&self.info.pub_key, mac_in, &mut mac_out[..16]);
        }

        Ok(packet)
    }

    pub fn process_incoming_handshake_response(&mut self, packet: &[u8]) -> Result<Option<u32>, Error> {
        let their_index = LittleEndian::read_u32(&packet[4..]);
        let mut session = mem::replace(&mut self.sessions.next, None).ok_or_else(|| err_msg("no next session"))?;
        let _ = session.noise.read_message(&packet[12..60], &mut [])?;

        session.their_index = their_index;

        let session = session.into_transport_mode();

        let current = mem::replace(&mut self.sessions.current, Some(session));
        let dead    = mem::replace(&mut self.sessions.past,    current);

        self.last_handshake = Some(Instant::now());
        self.last_tun_queue = None;
        Ok(dead.map(|session| session.our_index))
    }

    pub fn handle_incoming_transport(&mut self, addr: SocketAddr, packet: &[u8])
        -> Result<(Vec<u8>, Option<Option<u32>>), Error> {

        let     our_index  = LittleEndian::read_u32(&packet[4..]);
        let     nonce      = LittleEndian::read_u64(&packet[8..]);
        let mut raw_packet = vec![0u8; MAX_SEGMENT_SIZE];

        let session_type = {
            let (session, session_type) = self.find_session(our_index).ok_or_else(|| err_msg("no session with index"))?;
            ensure!(session.noise.is_handshake_finished(), "session is not ready for transport packets");

            session.anti_replay.update(nonce)?;
            session.noise.set_receiving_nonce(nonce)?;
            let len = session.noise.read_message(&packet[16..], &mut raw_packet)?;
            let len = IpPacket::new(&raw_packet[..len])
                .ok_or_else(||format_err!("invalid IP packet (len {})", len))?
                .length();
            raw_packet.truncate(len as usize);

            session.last_received = Some(Instant::now());

            session_type
        };

        let dead_index = if session_type == SessionType::Next {
            debug!("moving 'next' session to current after receiving first transport packet");
            let next    = std::mem::replace(&mut self.sessions.next, None);
            let current = std::mem::replace(&mut self.sessions.current, next);
            let dead    = std::mem::replace(&mut self.sessions.past, current);
            self.last_handshake = Some(Instant::now());
            self.last_tun_queue = None;
            Some(dead.map(|session| session.our_index))
        } else {
            None
        };

        self.rx_bytes     += packet.len() as u64;
        self.info.endpoint = Some(addr); // update peer endpoint after successful authentication

        Ok((raw_packet, dead_index))
    }

    pub fn handle_outgoing_transport(&mut self, packet: &[u8]) -> Result<(SocketAddr, Vec<u8>), Error> {
        let session        = self.sessions.current.as_mut().ok_or_else(|| err_msg("no current noise session"))?;
        let endpoint       = self.info.endpoint.ok_or_else(|| err_msg("no known peer endpoint"))?;
        let padding        = PADDING_MULTIPLE - (packet.len() % PADDING_MULTIPLE);
        let padded_len     = packet.len() + padding;
        let mut out_packet = vec![0u8; padded_len + TRANSPORT_OVERHEAD];

        let nonce = session.noise.sending_nonce()?;
        ensure!(nonce < REJECT_AFTER_MESSAGES, "exceeded maximum message count");

        out_packet[0] = 4;
        LittleEndian::write_u32(&mut out_packet[4..], session.their_index);
        LittleEndian::write_u64(&mut out_packet[8..], nonce);
        let padded_packet = &[packet, &vec![0u8; padding]].concat();
        let len = session.noise.write_message(padded_packet, &mut out_packet[16..])?;
        self.tx_bytes += len as u64;
        session.last_sent = Some(Instant::now());
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
        for &(ip, cidr) in &self.info.allowed_ips {
            s.push_str(&format!("allowed_ip={}/{}\n", ip, cidr));
        }
        s.push_str(&format!("tx_bytes={}\nrx_bytes={}\n", self.tx_bytes, self.rx_bytes));

        if let Some(ref last_handshake) = self.last_handshake {
            let system_now = SystemTime::now();
            let time_passed = Instant::now().duration_since(*last_handshake);
            if let Ok(time) = (system_now - time_passed).duration_since(UNIX_EPOCH) {
                s.push_str(&format!("last_handshake_time_sec={}\nlast_handshake_time_nsec={}\n",
                                    time.as_secs(), time.subsec_nanos()))
            } else {
                warn!("SystemTime Duration error");
            }
        }
        s
    }
}
