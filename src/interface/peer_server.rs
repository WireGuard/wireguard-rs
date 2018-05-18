use consts::{REKEY_TIMEOUT, KEEPALIVE_TIMEOUT, STALE_SESSION_TIMEOUT,
             MAX_CONTENT_SIZE, WIPE_AFTER_TIME, MAX_HANDSHAKE_ATTEMPTS,
             UNDER_LOAD_QUEUE_SIZE, UNDER_LOAD_TIME};
use cookie;
use interface::{SharedPeer, SharedState, State, UtunPacket};
use message::{Message, Initiation, Response, CookieReply, Transport};
use peer::{Peer, SessionType, SessionTransition};
use ratelimiter::RateLimiter;
use timestamp::Timestamp;
use timer::{Timer, TimerMessage};

use byteorder::{ByteOrder, LittleEndian};
use failure::{Error, err_msg};
use futures::{Async, Future, Stream, Poll, unsync::mpsc, task};
use rand::{self, Rng, ThreadRng};
use udp::{Endpoint, UdpSocket, PeerServerMessage, UdpChannel};
use tokio_core::reactor::Handle;

use std::collections::VecDeque;
use std::convert::TryInto;
use std::net::IpAddr;
use std::rc::Rc;
use std::time::Instant;

pub enum ChannelMessage {
    ClearPrivateKey,
    NewPrivateKey,
    NewListenPort(u16),
    NewFwmark(u32),
    NewPersistentKeepalive(SharedPeer),
    NewPeer(SharedPeer),
}

struct Channel<T> {
    tx: mpsc::UnboundedSender<T>,
    rx: mpsc::UnboundedReceiver<T>,
}

impl<T> From<(mpsc::UnboundedSender<T>, mpsc::UnboundedReceiver<T>)> for Channel<T> {
    fn from(pair: (mpsc::UnboundedSender<T>, mpsc::UnboundedReceiver<T>)) -> Self {
        Self {
            tx: pair.0,
            rx: pair.1,
        }
    }
}

pub struct PeerServer {
    handle           : Handle,
    shared_state     : SharedState,
    udp              : Option<UdpChannel>,
    port             : Option<u16>,
    outgoing         : Channel<UtunPacket>,
    channel          : Channel<ChannelMessage>,
    handshakes       : VecDeque<(Endpoint, Message)>,
    timer            : Timer,
    tunnel_tx        : mpsc::UnboundedSender<Vec<u8>>,
    cookie           : cookie::Validator,
    rate_limiter     : RateLimiter,
    under_load_until : Instant,
    rng              : ThreadRng,
}

impl PeerServer {
    pub fn new(handle: Handle, shared_state: SharedState, tunnel_tx: mpsc::UnboundedSender<Vec<u8>>) -> Result<Self, Error> {
        Ok(PeerServer {
            shared_state, tunnel_tx,
            handle           : handle.clone(),
            timer            : Timer::new(handle.clone()),
            udp              : None,
            port             : None,
            outgoing         : mpsc::unbounded().into(),
            channel          : mpsc::unbounded().into(),
            handshakes       : VecDeque::new(),
            cookie           : cookie::Validator::new(&[0u8; 32]),
            rate_limiter     : RateLimiter::new(&handle)?,
            under_load_until : Instant::now(),
            rng              : rand::thread_rng()
        })
    }

    pub fn rebind(&mut self) -> Result<(), Error> {
        let interface = &self.shared_state.borrow().interface_info;

        if interface.private_key.is_none() {
            self.udp  = None;
            self.port = None;
            return Ok(());
        }

        let port   = interface.listen_port.unwrap_or(0);
        let fwmark = interface.fwmark.unwrap_or(0);

        if self.port.is_some() && self.port.unwrap() == port {
            debug!("skipping rebind, since we're already listening on the correct port.");
            return Ok(())
        }

        let socket = UdpSocket::bind(port, self.handle.clone())?;
        info!("listening on {:?}", socket.local_addrs()?);

        let udp: UdpChannel = socket.framed().into();

        if fwmark != 0 {
            udp.set_mark(fwmark)?;
        }

        // TODO: clear out peer sticky endpoint sources
        self.udp  = Some(udp);
        self.port = Some(port);
        Ok(())
    }

    pub fn tunnel_tx(&self) -> mpsc::UnboundedSender<UtunPacket> {
        self.outgoing.tx.clone()
    }

    pub fn tx(&self) -> mpsc::UnboundedSender<ChannelMessage> {
        self.channel.tx.clone()
    }

    fn send_to_peer(&self, payload: PeerServerMessage) -> Result<(), Error> {
        self.udp.as_ref().ok_or_else(|| err_msg("no udp socket"))?
            .send(payload);
        Ok(())
    }

    fn send_to_tunnel(&self, packet: Vec<u8>) -> Result<(), Error> {
        self.tunnel_tx.unbounded_send(packet).map_err(|e| e.into())
    }

    fn unused_index(&mut self, state: &mut State) -> u32 {
        loop {
            let tentative: u32 = self.rng.gen();
            if !state.index_map.contains_key(&tentative) {
                return tentative;
            }
        }
    }

    fn under_load(&mut self) -> bool {
        let now = Instant::now();

        if self.handshakes.len() > UNDER_LOAD_QUEUE_SIZE {
            self.under_load_until = now + *UNDER_LOAD_TIME;
        }

        self.under_load_until > now
    }

    fn handle_ingress_packet(&mut self, addr: Endpoint, packet: Vec<u8>) -> Result<(), Error> {
        trace!("got a UDP packet from {:?} of length {}, packet type {}", &addr, packet.len(), packet[0]);

        let message = packet.try_into()?;
        if let Message::Transport(packet) = message {
            self.handle_ingress_transport(addr, &packet)?;
        } else {
            self.queue_ingress_handshake(addr, message);
        }
        Ok(())
    }

    fn queue_ingress_handshake(&mut self, addr: Endpoint, message: Message) {
        // TODO: max queue size management
        self.handshakes.push_back((addr, message));
        task::current().notify();
    }

    fn handle_ingress_handshake(&mut self, addr: Endpoint, message: &Message) -> Result<(), Error> {
        if self.under_load() {
            info!("we're under load, captain.");
        }

        match message {
            Message::Initiation(ref packet)  => self.handle_ingress_handshake_init(addr, packet)?,
            Message::Response(ref packet)    => self.handle_ingress_handshake_resp(addr, packet)?,
            Message::CookieReply(ref packet) => self.handle_ingress_cookie_reply(addr, packet)?,
            Message::Transport(_)            => unreachable!("no transport packets allowed"),
        }
        Ok(())
    }

    fn handle_ingress_handshake_init(&mut self, addr: Endpoint, packet: &Initiation) -> Result<(), Error> {
        ensure!(packet.len() == 148, "handshake init packet length is incorrect");

        let shared_state      = self.shared_state.clone();
        let mut state         = shared_state.borrow_mut();
        let (mac_in, mac_out) = packet.split_at(116);
        self.cookie.verify_mac1(&mac_in[..], &mac_out[..16])?;

        if self.under_load() {
            let mac2_verified = match addr.ip() {
                IpAddr::V4(ip) => self.cookie.verify_mac2(&packet, &ip.octets()).is_ok(),
                IpAddr::V6(ip) => self.cookie.verify_mac2(&packet, &ip.octets()).is_ok(),
            };

            if !mac2_verified {
                bail!("would send cookie request now");
            }

            if !self.rate_limiter.allow(&addr.ip()) {
                bail!("rejected by rate limiter.");
            }
        }

        debug!("got handshake initiation request (0x01)");

        let handshake = Peer::process_incoming_handshake(
            &state.interface_info.private_key.ok_or_else(|| err_msg("no private key!"))?,
            packet)?;

        let peer_ref = state.pubkey_map.get(handshake.their_pubkey())
            .ok_or_else(|| err_msg("unknown peer pubkey"))?.clone();

        let index = self.unused_index(&mut state);
        let (response, dead_index) = peer_ref.borrow_mut().complete_incoming_handshake(addr, index, handshake)?;
        if let Some(index) = dead_index {
            let _ = state.index_map.remove(&index);
        }
        let _ = state.index_map.insert(index, peer_ref.clone());

        self.send_to_peer((addr, response))?;
        info!("sent handshake response (index {}).", index);

        Ok(())
    }

    fn handle_ingress_handshake_resp(&mut self, addr: Endpoint, packet: &Response) -> Result<(), Error> {
        ensure!(packet.len() == 92, "handshake resp packet length is incorrect");

        let mut state         = self.shared_state.borrow_mut();
        let (mac_in, mac_out) = packet.split_at(60);
        self.cookie.verify_mac1(&mac_in[..], &mac_out[..16])?;

        debug!("got handshake response (0x02)");

        let our_index = LittleEndian::read_u32(&packet[8..]);
        let peer_ref  = state.index_map.get(&our_index)
            .ok_or_else(|| format_err!("unknown our_index ({})", our_index))?
            .clone();
        let mut peer = peer_ref.borrow_mut();
        let dead_index = peer.process_incoming_handshake_response(addr, packet)?;
        if let Some(index) = dead_index {
            let _ = state.index_map.remove(&index);
        }

        if peer.ready_for_transport() {
            if !peer.outgoing_queue.is_empty() {
                debug!("sending {} queued egress packets", peer.outgoing_queue.len());
                while let Some(packet) = peer.outgoing_queue.pop_front() {
                    self.send_to_peer(peer.handle_outgoing_transport(packet.payload())?)?;
                }
            } else {
                self.send_to_peer(peer.handle_outgoing_transport(&[])?)?;
            }
        } else {
            error!("peer not ready for transport after processing handshake response. this shouldn't happen.");
        }
        info!("handshake response received, current session now {}", our_index);

        self.timer.send_after(*WIPE_AFTER_TIME, TimerMessage::Wipe(Rc::downgrade(&peer_ref)));
        Ok(())
    }

    fn handle_ingress_cookie_reply(&mut self, _addr: Endpoint, packet: &CookieReply) -> Result<(), Error> {
        let     state    = self.shared_state.borrow_mut();
        let     peer_ref = state.index_map.get(&packet.our_index()).ok_or_else(|| err_msg("unknown our_index"))?.clone();
        let mut peer     = peer_ref.borrow_mut();

        peer.consume_cookie_reply(packet)
    }

    fn handle_ingress_transport(&mut self, addr: Endpoint, packet: &Transport) -> Result<(), Error> {
        let peer_ref = self.shared_state.borrow().index_map.get(&packet.our_index())
            .ok_or_else(|| err_msg("unknown our_index"))?.clone();

        let (raw_packet, needs_handshake) = {
            let mut peer = peer_ref.borrow_mut();
            let mut state = self.shared_state.borrow_mut();
            let (raw_packet, transition) = peer.handle_incoming_transport(addr, packet)?;

            if let SessionTransition::Transition(possible_dead_index) = transition {
                if let Some(index) = possible_dead_index {
                    let _ = state.index_map.remove(&index);
                }

                let outgoing: Vec<UtunPacket> = peer.outgoing_queue.drain(..).collect();

                for packet in outgoing {
                    match peer.handle_outgoing_transport(packet.payload()) {
                        Ok(message) => self.send_to_peer(message)?,
                        Err(e) => warn!("failed to encrypt packet: {}", e)
                    }
                }

                self.timer.send_after(*WIPE_AFTER_TIME, TimerMessage::Wipe(Rc::downgrade(&peer_ref)));
            }
            (raw_packet, peer.needs_new_handshake(false))
        };

        if needs_handshake {
            debug!("sending handshake init on recv because peer says it needs it");
            self.send_handshake_init(&peer_ref)?;
        }

        if raw_packet.is_empty() {
            debug!("received keepalive.");
            return Ok(()) // short-circuit on keep-alives
        }

        self.shared_state.borrow_mut().router.validate_source(&raw_packet, &peer_ref)?;
        trace!("received transport packet");
        self.send_to_tunnel(raw_packet)?;
        Ok(())
    }

    fn handle_egress_packet(&mut self, packet: UtunPacket) -> Result<(), Error> {
        ensure!(!packet.payload().is_empty() && packet.payload().len() <= MAX_CONTENT_SIZE, "egress packet outside of size bounds");

        let peer_ref = self.shared_state.borrow_mut().router.route_to_peer(packet.payload())
            .ok_or_else(|| err_msg("no route to peer"))?;

        let needs_handshake = {
            let mut peer = peer_ref.borrow_mut();
            let needs_handshake = peer.needs_new_handshake(true);
            peer.queue_egress(packet);

            if peer.ready_for_transport() {
                if peer.outgoing_queue.len() > 1 {
                    debug!("sending {} queued egress packets", peer.outgoing_queue.len());
                }

                while let Some(packet) = peer.outgoing_queue.pop_front() {
                    self.send_to_peer(peer.handle_outgoing_transport(packet.payload())?)?;
                }
            }

            needs_handshake
        };

        if needs_handshake {
            debug!("sending handshake init on send because peer says it needs it");
            self.send_handshake_init(&peer_ref)?;
        }
        Ok(())
    }

    fn send_handshake_init(&mut self, peer_ref: &SharedPeer) -> Result<u32, Error> {
        let     shared_state = self.shared_state.clone();
        let mut state        = shared_state.borrow_mut();
        let mut peer         = peer_ref.borrow_mut();

        if peer.timers.handshake_initialized.elapsed() < *REKEY_TIMEOUT {
            bail!("skipping handshake init because of REKEY_TIMEOUT");
        }

        let private_key = &state.interface_info.private_key.ok_or_else(|| err_msg("no private key!"))?;
        let new_index   = self.unused_index(&mut state);

        let (endpoint, init_packet, dead_index) = peer.initiate_new_session(private_key, new_index)?;
        let _ = state.index_map.insert(new_index, peer_ref.clone());

        if let Some(index) = dead_index {
            trace!("removing abandoned 'next' session ({}) from index map", index);
            let _ = state.index_map.remove(&index);
        }

        self.send_to_peer((endpoint, init_packet))?;
        peer.timers.handshake_initialized = Timestamp::now();
        self.timer.send_after(*REKEY_TIMEOUT, TimerMessage::Rekey(Rc::downgrade(&peer_ref), new_index));
        Ok(new_index)
    }

    fn handle_timer(&mut self, message: TimerMessage) -> Result<(), Error> {
        use self::TimerMessage::*;
        match message {
            Rekey(peer_ref, our_index) => {
                let mut upgraded_peer_ref = peer_ref.upgrade()
                    .ok_or_else(|| err_msg("peer no longer there"))?;
                {
                    // TODO: clear sticky source endpoint if retrying, in case that is the problem
                    let mut peer = upgraded_peer_ref.borrow_mut();

                    match peer.find_session(our_index) {
                        Some((_, SessionType::Next)) => {
                            if peer.timers.handshake_initialized.elapsed() < *REKEY_TIMEOUT {
                                let wait = *REKEY_TIMEOUT - peer.timers.handshake_initialized.elapsed();
                                self.timer.send_after(wait, Rekey(peer_ref.clone(), our_index));
                                bail!("too soon since last init sent, waiting {:?} ({})", wait, our_index);
                            } else if peer.timers.handshake_attempts >= *MAX_HANDSHAKE_ATTEMPTS {
                                bail!("REKEY_ATTEMPT_TIME exceeded, giving up.");
                            }
                            peer.timers.handshake_attempts += 1;
                            debug!("sending hanshake init (rekey attempt #{})", peer.timers.handshake_attempts);
                        },
                        Some((_, SessionType::Current)) => {
                            let since_last_send = peer.timers.data_sent.elapsed();
                            let since_last_auth_recv = peer.timers.authenticated_received.elapsed();
                            if since_last_send > since_last_auth_recv {
                                self.timer.send_after(*STALE_SESSION_TIMEOUT, Rekey(peer_ref.clone(), our_index));
                                bail!("stale rekey tick (waiting ~{}s, inactive)", STALE_SESSION_TIMEOUT.as_secs());
                            } else if since_last_auth_recv <= *STALE_SESSION_TIMEOUT {
                                let wait = *STALE_SESSION_TIMEOUT - since_last_auth_recv;
                                self.timer.send_after(wait, Rekey(peer_ref.clone(), our_index));
                                bail!("stale rekey tick (waiting ~{}s, not enough time passed yet)", wait.as_secs());
                            }
                            debug!("sending hanshake init (stale session rekey)");
                        },
                        _ => bail!("index is linked to a dead session, bailing ({})", our_index)
                    }
                }

                self.send_handshake_init(&upgraded_peer_ref)?;
            },
            PassiveKeepAlive(peer_ref) => {
                let mut upgraded_peer_ref = peer_ref.upgrade().ok_or_else(|| err_msg("peer no longer there"))?;
                let mut peer = upgraded_peer_ref.borrow_mut();
                {
                    if peer.sessions.current.is_none() {
                        self.timer.send_after(*KEEPALIVE_TIMEOUT, PassiveKeepAlive(peer_ref.clone()));
                        bail!("passive keepalive skip: no active session. waiting until there is one.");
                    } else if peer.info.keepalive.is_some() {
                        self.timer.send_after(*KEEPALIVE_TIMEOUT, PassiveKeepAlive(peer_ref.clone()));
                        bail!("passive keepalive skip: persistent keepalive set.");
                    }

                    let since_last_recv = peer.timers.data_received.elapsed();
                    let since_last_send = peer.timers.data_sent.elapsed();
                    if peer.timers.keepalive_sent {
                        self.timer.send_after(*KEEPALIVE_TIMEOUT, PassiveKeepAlive(peer_ref.clone()));
                        bail!("passive keepalive already sent (waiting {}s to see if session survives)", KEEPALIVE_TIMEOUT.as_secs());
                    } else if since_last_send < since_last_recv {
                        self.timer.send_after(*KEEPALIVE_TIMEOUT, PassiveKeepAlive(peer_ref.clone()));
                        bail!("passive keepalive tick (last data was send not recv)")
                    } else if since_last_recv < *KEEPALIVE_TIMEOUT {
                        let wait = *KEEPALIVE_TIMEOUT - since_last_recv;
                        self.timer.send_after(wait, PassiveKeepAlive(peer_ref.clone()));
                        bail!("passive keepalive tick (waiting ~{}s due to last recv time)", wait.as_secs());
                    } else {
                        peer.timers.keepalive_sent = true;
                    }
                }

                self.send_to_peer(peer.handle_outgoing_transport(&[])?)?;
                debug!("sent passive keepalive packet");

                self.timer.send_after(*KEEPALIVE_TIMEOUT, PassiveKeepAlive(peer_ref.clone()));
            },
            PersistentKeepAlive(peer_ref) => {
                let mut upgraded_peer_ref = peer_ref.upgrade().ok_or_else(|| err_msg("peer no longer there"))?;
                let mut peer = upgraded_peer_ref.borrow_mut();

                if let Some(persistent_keepalive) = peer.info.persistent_keepalive() {
                    let since_last_auth_any = peer.timers.authenticated_traversed.elapsed();
                    if since_last_auth_any < persistent_keepalive {
                        let wait = persistent_keepalive - since_last_auth_any;
                        let handle = self.timer.send_after(wait, PersistentKeepAlive(peer_ref.clone()));
                        peer.timers.persistent_timer = Some(handle);
                        bail!("persistent keepalive tick (waiting ~{}s due to last authenticated packet time)", wait.as_secs());
                    }

                    self.send_to_peer(peer.handle_outgoing_transport(&[])?)?;
                    let handle = self.timer.send_after(persistent_keepalive, PersistentKeepAlive(peer_ref.clone()));
                    peer.timers.persistent_timer = Some(handle);
                    debug!("sent persistent keepalive packet");
                } else {
                    bail!("no persistent keepalive set for peer (likely unset between the time the timer was started and now).");
                }
            },
            Wipe(peer_ref) => {
                let mut upgraded_peer_ref = peer_ref.upgrade().ok_or_else(|| err_msg("peer no longer there"))?;
                let mut peer = upgraded_peer_ref.borrow_mut();
                let mut state = self.shared_state.borrow_mut();
                if peer.timers.handshake_completed.elapsed() >= *WIPE_AFTER_TIME {
                    info!("wiping all old sessions due to staleness timeout for peer {}", peer.info);
                    for index in peer.sessions.wipe() {
                        let _ = state.index_map.remove(&index);
                    }
                } else {
                    debug!("skipping wipe timer for since activity has happened since triggered. ({})", peer.info);
                }
            }
        }
        Ok(())
    }

    fn handle_incoming_event(&mut self, event: ChannelMessage) -> Result<(), Error> {
        use self::ChannelMessage::*;
        match event {
            NewPrivateKey => {
                let pub_key = self.shared_state.borrow().interface_info.pub_key;
                if let Some(ref pub_key) = pub_key {
                    self.cookie = cookie::Validator::new(pub_key);
                    if self.udp.is_none() {
                        self.rebind().unwrap();
                    }
                } else {
                    self.udp  = None;
                    self.port = None;
                }
            },
            NewPeer(peer_ref) => {
                let mut peer = peer_ref.borrow_mut();
                self.timer.send_after(*KEEPALIVE_TIMEOUT, TimerMessage::PassiveKeepAlive(Rc::downgrade(&peer_ref)));
                if let Some(keepalive) = peer.info.persistent_keepalive() {
                    let handle = self.timer.send_after(keepalive, TimerMessage::PersistentKeepAlive(Rc::downgrade(&peer_ref)));
                    peer.timers.persistent_timer = Some(handle);
                }
            },
            NewPersistentKeepalive(peer_ref) => {
                let mut peer = peer_ref.borrow_mut();
                if let Some(ref mut handle) = peer.timers.persistent_timer {
                    handle.cancel();
                    debug!("sent cancel signal to old persistent_timer.");
                }

                if let Some(keepalive) = peer.info.persistent_keepalive() {
                    let handle = self.timer.send_after(keepalive, TimerMessage::PersistentKeepAlive(Rc::downgrade(&peer_ref)));
                    peer.timers.persistent_timer = Some(handle);
                    self.send_to_peer(peer.handle_outgoing_transport(&[])?)?;
                    debug!("set new keepalive timer and immediately sent new keepalive packet.");
                }
            }
            NewListenPort(_) => self.rebind()?,
            NewFwmark(mark) => {
                if let Some(ref udp) = self.udp {
                    udp.set_mark(mark)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl Future for PeerServer {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Poll inner Futures until at least one of them has returned a NotReady. It's not
        // safe to return NotReady yourself unless at least one future has returned a NotReady.
        loop {
            let mut not_ready = false;
            // Handle config events
            match self.channel.rx.poll() {
                Ok(Async::Ready(Some(event))) => {
                    let _ = self.handle_incoming_event(event);
                },
                Ok(Async::NotReady)    => { not_ready = true; },
                Ok(Async::Ready(None)) => bail!("config stream ended unexpectedly"),
                Err(e)                 => bail!("config stream error: {:?}", e),
            }

            // Handle pending state-changing timers
            match self.timer.poll() {
                Ok(Async::Ready(Some(message))) => {
                    let _ = self.handle_timer(message).map_err(|e| debug!("TIMER: {}", e));
                },
                Ok(Async::NotReady)    => { not_ready = true; },
                Ok(Async::Ready(None)) => bail!("timer stream ended unexpectedly"),
                Err(e)                 => bail!("timer stream error: {:?}", e),
            }

            // Handle UDP packets from the outside world
            if self.udp.is_some() {
                match self.udp.as_mut().unwrap().ingress.poll() {
                    Ok(Async::Ready(Some((addr, packet)))) => {
                        let _ = self.handle_ingress_packet(addr, packet).map_err(|e| warn!("UDP ERR: {:?}", e));
                    },
                    Ok(Async::NotReady)    => { not_ready = true; },
                    Ok(Async::Ready(None)) => bail!("incoming udp stream ended unexpectedly"),
                    Err(e)                 => bail!("incoming udp stream error: {:?}", e)
                }
            }

            // Handle packets coming from the local tunnel
            match self.outgoing.rx.poll() {
                Ok(Async::Ready(Some(packet))) => {
                    let _ = self.handle_egress_packet(packet).map_err(|e| warn!("UDP ERR: {:?}", e));
                },
                Ok(Async::NotReady)    => { not_ready = true; },
                Ok(Async::Ready(None)) => bail!("outgoing udp stream ended unexpectedly"),
                Err(e)                 => bail!("outgoing udp stream error: {:?}", e),
            }

            if not_ready {
                break;
            }
        }

        if let Some((addr, message)) = self.handshakes.pop_front() {
            let _ = self.handle_ingress_handshake(addr, &message).map_err(|e| warn!("handshake err: {:?}", e));
        }

        Ok(Async::NotReady)
    }
}
