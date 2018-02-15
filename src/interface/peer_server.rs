use super::{SharedState, UtunPacket, trace_packet};
use consts::{REKEY_TIMEOUT, REKEY_AFTER_TIME, REJECT_AFTER_TIME, REKEY_ATTEMPT_TIME, KEEPALIVE_TIMEOUT, MAX_CONTENT_SIZE, TIMER_TICK_DURATION};
use interface::SharedPeer;
use protocol::{Peer, SessionType};
use noise::Noise;
use timer::{Timer, TimerMessage};

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use byteorder::{ByteOrder, LittleEndian};
use failure::{Error, err_msg};
use futures::{self, Async, Future, Stream, Sink, Poll, unsync, stream};
use socket2::{Socket, Domain, Type, Protocol};
use tokio_core::net::{UdpSocket, UdpCodec, UdpFramed};
use tokio_core::reactor::Handle;


pub type PeerServerMessage = (SocketAddr, Vec<u8>);
struct VecUdpCodec;
impl UdpCodec for VecUdpCodec {
    type In = PeerServerMessage;
    type Out = PeerServerMessage;

    fn decode(&mut self, src: &SocketAddr, buf: &[u8]) -> io::Result<Self::In> {
        let unmapped_ip = match src.ip() {
            IpAddr::V6(v6addr) => {
                if let Some(v4addr) = v6addr.to_ipv4() {
                    IpAddr::V4(v4addr)
                } else {
                    IpAddr::V6(v6addr)
                }
            }
            v4addr => v4addr
        };
        Ok((SocketAddr::new(unmapped_ip, src.port()), buf.to_vec()))
    }

    fn encode(&mut self, msg: Self::Out, buf: &mut Vec<u8>) -> SocketAddr {
        let (mut addr, mut data) = msg;
        buf.append(&mut data);
        let mapped_ip = match addr.ip() {
            IpAddr::V4(v4addr) => IpAddr::V6(v4addr.to_ipv6_mapped()),
            v6addr => v6addr
        };
        addr.set_ip(mapped_ip);
        addr
    }
}

pub struct PeerServer {
    handle: Handle,
    shared_state: SharedState,
    udp_stream: stream::SplitStream<UdpFramed<VecUdpCodec>>,
    timer: Timer,
    outgoing_tx: unsync::mpsc::Sender<UtunPacket>,
    outgoing_rx: futures::stream::Peekable<unsync::mpsc::Receiver<UtunPacket>>,
    udp_tx: unsync::mpsc::Sender<(SocketAddr, Vec<u8>)>,
    tunnel_tx: unsync::mpsc::Sender<UtunPacket>,
}

impl PeerServer {
    pub fn bind(handle: Handle, shared_state: SharedState, tunnel_tx: unsync::mpsc::Sender<UtunPacket>) -> Result<Self, Error> {
        let socket = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp()))?;
        socket.set_only_v6(false)?;
        socket.set_nonblocking(true)?;
        socket.bind(&SocketAddr::from((Ipv6Addr::unspecified(), 0)).into())?;
        let timer = Timer::new();
        let socket = UdpSocket::from_socket(socket.into_udp_socket(), &handle.clone())?;
        let (udp_sink, udp_stream) = socket.framed(VecUdpCodec{}).split();
        let (udp_tx, udp_rx) = unsync::mpsc::channel::<(SocketAddr, Vec<u8>)>(1024);
        let (outgoing_tx, outgoing_rx) = unsync::mpsc::channel::<UtunPacket>(1024);
        let outgoing_rx = outgoing_rx.peekable();

        let udp_write_passthrough = udp_sink.sink_map_err(|_| ()).send_all(
            udp_rx.map(|(addr, packet)| {
                trace!("sending UDP packet to {:?}", &addr);
                (addr, packet)
            }).map_err(|_| ()))
            .then(|_| Ok(()));
        handle.spawn(udp_write_passthrough);

        Ok(PeerServer {
            handle, shared_state, timer, udp_stream, udp_tx, tunnel_tx, outgoing_tx, outgoing_rx
        })
    }

    pub fn tx(&self) -> unsync::mpsc::Sender<UtunPacket> {
        self.outgoing_tx.clone()
    }

    fn send_to_peer(&self, payload: PeerServerMessage) {
        self.handle.spawn(self.udp_tx.clone().send(payload).then(|_| Ok(())));
    }

    fn send_to_tunnel(&self, packet: UtunPacket) {
        self.handle.spawn(self.tunnel_tx.clone().send(packet).then(|_| Ok(())));
    }

    fn handle_incoming_packet(&mut self, addr: SocketAddr, packet: &[u8]) -> Result<(), Error> {
        trace!("got a UDP packet from {:?} of length {}, packet type {}", &addr, packet.len(), packet[0]);
        let mut state = self.shared_state.borrow_mut();
        match packet[0] {
            1 => {
                ensure!(packet.len() == 148, "handshake init packet length is incorrect");
                {
                    let pubkey = state.interface_info.pub_key.as_ref()
                        .ok_or_else(|| err_msg("must have local interface key"))?;
                    let (mac_in, mac_out) = packet.split_at(116);
                    Noise::verify_mac1(pubkey, mac_in, &mac_out[..16])?;
                }

                debug!("got handshake initiation request (0x01)");

                let handshake = Peer::process_incoming_handshake(
                    &state.interface_info.private_key.ok_or_else(|| err_msg("no private key!"))?,
                    packet)?;

                let peer_ref = state.pubkey_map.get(handshake.their_pubkey())
                    .ok_or_else(|| err_msg("unknown peer pubkey"))?.clone();

                let mut peer = peer_ref.borrow_mut();
                let (response, next_index) = peer.complete_incoming_handshake(addr, handshake)?;
                let _ = state.index_map.insert(next_index, peer_ref.clone());

                self.send_to_peer((addr, response));
                info!("sent handshake response, ratcheted session (index {}).", next_index);
            },
            2 => {
                ensure!(packet.len() == 92, "handshake resp packet length is incorrect");
                {
                    let pubkey = state.interface_info.pub_key.as_ref()
                        .ok_or_else(|| err_msg("must have local interface key"))?;
                    let (mac_in, mac_out) = packet.split_at(60);
                    Noise::verify_mac1(pubkey, mac_in, &mac_out[..16])?;
                }
                debug!("got handshake response (0x02)");

                let our_index = LittleEndian::read_u32(&packet[8..]);
                let peer_ref  = state.index_map.get(&our_index)
                    .ok_or_else(|| format_err!("unknown our_index ({})", our_index))?
                    .clone();
                let mut peer = peer_ref.borrow_mut();
                let dead_index = peer.process_incoming_handshake_response(packet)?;
                if let Some(index) = dead_index {
                    let _ = state.index_map.remove(&index);
                }
                info!("handshake response received, current session now {}", our_index);

                self.timer.spawn_delayed(&self.handle,
                                         *KEEPALIVE_TIMEOUT,
                                         TimerMessage::PassiveKeepAlive(peer_ref.clone(), our_index));

                self.timer.spawn_delayed(&self.handle,
                                         *REJECT_AFTER_TIME,
                                         TimerMessage::Reject(peer_ref.clone(), our_index));

                if let Some(persistent_keep_alive) = peer.info.keep_alive_interval {
                    self.timer.spawn_delayed(&self.handle,
                                             Duration::from_secs(persistent_keep_alive as u64),
                                             TimerMessage::PersistentKeepAlive(peer_ref.clone(), our_index));
                }
            },
            3 => {
                warn!("cookie messages not yet implemented.");
            },
            4 => {
                let our_index_received = LittleEndian::read_u32(&packet[4..]);

                let peer_ref = state.index_map.get(&our_index_received)
                    .ok_or_else(|| err_msg("unknown our_index"))?
                    .clone();

                let (raw_packet, dead_index) = {
                    let mut peer = peer_ref.borrow_mut();
                    peer.handle_incoming_transport(addr, &packet)?
                };

                if let Some(index) = dead_index {
                    let _ = state.index_map.remove(&index);
                }

                if raw_packet.is_empty() {
                    debug!("received keepalive.");
                    return Ok(()) // short-circuit on keep-alives
                }

                state.router.validate_source(&raw_packet, &peer_ref)?;

                trace_packet("received TRANSPORT: ", &raw_packet);
                self.send_to_tunnel(UtunPacket::from(raw_packet)?);
            },
            _ => bail!("unknown wireguard message type")
        }
        Ok(())
    }

    fn send_handshake_init(&mut self, peer_ref: SharedPeer) -> Result<u32, Error> {
        let mut state       = self.shared_state.borrow_mut();
        let mut peer        = peer_ref.borrow_mut();
        let     private_key = &state.interface_info.private_key.ok_or_else(|| err_msg("no private key!"))?;

        let (endpoint, init_packet, new_index, dead_index) = peer.initiate_new_session(private_key)?;

        let _ = state.index_map.insert(new_index, peer_ref.clone());
        if let Some(index) = dead_index {
            trace!("removing abandoned 'next' session ({}) from index map", index);
            let _ = state.index_map.remove(&index);
        }

        self.send_to_peer((endpoint, init_packet));
        peer.last_rekey_init = Some(Instant::now());
        let when = *REKEY_TIMEOUT + *TIMER_TICK_DURATION * 2;
        self.timer.spawn_delayed(&self.handle,
                                 when,
                                 TimerMessage::Rekey(peer_ref.clone(), new_index));
        Ok(new_index)
    }

    fn handle_timer(&mut self, message: TimerMessage) -> Result<(), Error> {
        match message {
            TimerMessage::Rekey(peer_ref, our_index) => {
                {
                    let mut peer = peer_ref.borrow_mut();
                    let     now  = Instant::now();

                    match peer.find_session(our_index) {
                        Some((_, SessionType::Next)) => {
                            if let Some(last_init_sent) = peer.last_rekey_init {
                                let since_last_init = now.duration_since(last_init_sent);
                                if since_last_init < *REKEY_TIMEOUT {
                                    let wait = *REKEY_TIMEOUT - since_last_init + *TIMER_TICK_DURATION * 2;
                                    self.timer.spawn_delayed(&self.handle,
                                                             wait,
                                                             TimerMessage::Rekey(peer_ref.clone(), our_index));
                                    bail!("too soon since last init sent, waiting {:?} ({})", wait, our_index);
                                } else if since_last_init > *REKEY_ATTEMPT_TIME {
                                    bail!("REKEY_ATTEMPT_TIME exceeded ({})", our_index);
                                }
                            }
                        },
                        Some((_, SessionType::Current)) => {
                            if let Some(last_handshake) = peer.last_handshake_instant {
                                let since_last_handshake = now.duration_since(last_handshake);
                                if since_last_handshake <= *REKEY_AFTER_TIME {
                                    let wait = *REKEY_AFTER_TIME - since_last_handshake + *TIMER_TICK_DURATION * 2;
                                    self.timer.spawn_delayed(&self.handle,
                                                             wait,
                                                             TimerMessage::Rekey(peer_ref.clone(), our_index));
                                    bail!("recent last complete handshake - waiting {:?} ({})", wait, our_index);
                                }
                            }
                        },
                        _ => bail!("index is linked to a dead session, bailing.")
                    }
                }

                let new_index = self.send_handshake_init(peer_ref.clone())?;
                debug!("sent handshake init (Rekey timer) ({} -> {})", our_index, new_index);

            },
            TimerMessage::Reject(peer_ref, our_index) => {
                let mut peer  = peer_ref.borrow_mut();
                let mut state = self.shared_state.borrow_mut();

                debug!("rejection timeout for session {}, ejecting", our_index);

                match peer.find_session(our_index) {
                    Some((_, SessionType::Next))    => { peer.sessions.next = None; },
                    Some((_, SessionType::Current)) => { peer.sessions.current = None; },
                    Some((_, SessionType::Past))    => { peer.sessions.past = None; },
                    None                            => debug!("reject timeout for already-killed session")
                }
                let _ = state.index_map.remove(&our_index);
            },
            TimerMessage::PassiveKeepAlive(peer_ref, our_index) => {
                let mut peer = peer_ref.borrow_mut();
                {
                    let (session, session_type) = peer.find_session(our_index).ok_or_else(|| err_msg("missing session for timer"))?;
                    ensure!(session_type == SessionType::Current, "expired session for passive keepalive timer");

                    if let Some(last_sent) = session.last_sent {
                        let last_sent_packet = Instant::now().duration_since(last_sent);
                        if last_sent_packet < *KEEPALIVE_TIMEOUT {
                            self.timer.spawn_delayed(&self.handle,
                                                     *KEEPALIVE_TIMEOUT - last_sent_packet + *TIMER_TICK_DURATION,
                                                     TimerMessage::PassiveKeepAlive(peer_ref.clone(), our_index));
                            bail!("passive keepalive tick (waiting {:?})", *KEEPALIVE_TIMEOUT - last_sent_packet);
                        }
                    }
                }

                self.send_to_peer(peer.handle_outgoing_transport(&[])?);
                debug!("sent passive keepalive packet ({})", our_index);

                self.timer.spawn_delayed(&self.handle,
                                         *KEEPALIVE_TIMEOUT,
                                         TimerMessage::PassiveKeepAlive(peer_ref.clone(), our_index));
            },
            TimerMessage::PersistentKeepAlive(peer_ref, our_index) => {
                let mut peer = peer_ref.borrow_mut();
                {
                    let (_, session_type) = peer.find_session(our_index).ok_or_else(|| err_msg("missing session for timer"))?;
                    ensure!(session_type == SessionType::Current, "expired session for persistent keepalive timer");
                }

                self.send_to_peer(peer.handle_outgoing_transport(&[])?);
                debug!("sent persistent keepalive packet ({})", our_index);

                if let Some(persistent_keepalive) = peer.info.keep_alive_interval {
                    self.timer.spawn_delayed(&self.handle,
                                             Duration::from_secs(persistent_keepalive as u64),
                                             TimerMessage::PersistentKeepAlive(peer_ref.clone(), our_index));

                }
            }
        }
        Ok(())
    }

    // Just this way to avoid a double-mutable-borrow while peeking.
    fn peek_from_tun_and_handle(&mut self) -> Result<bool, Error> {
        enum Decision { Drop, Wait, Handshake(SharedPeer), Transport((SocketAddr, Vec<u8>))}
        let decision = {
            let packet = match self.outgoing_rx.peek() {
                Ok(Async::Ready(Some(packet))) => packet,
                Ok(Async::NotReady) => return Ok(false),
                Ok(Async::Ready(None)) | Err(_) => bail!("channel failure"),
            };
            trace_packet("received UTUN packet: ", packet.payload());

            let mut state    = self.shared_state.borrow_mut();
            let     peer_ref = state.router.route_to_peer(packet.payload()).ok_or_else(|| err_msg("no route to peer"))?;
            let mut peer     = peer_ref.borrow_mut();

            if packet.payload().is_empty() || packet.payload().len() > MAX_CONTENT_SIZE {
                Decision::Drop
            } else if peer.sessions.current.is_none() {
                if peer.sessions.next.is_some() {
                    Decision::Wait
                } else {
                    Decision::Handshake(peer_ref.clone())
                }
            } else {
                Decision::Transport(peer.handle_outgoing_transport(packet.payload())?)
            }
        };

        match decision {
            Decision::Transport(outgoing) => {
                self.send_to_peer(outgoing);
                let _ = self.outgoing_rx.poll();
                Ok(true)
            },
            Decision::Handshake(peer_ref) => {
                debug!("kicking off handshake because there are pending outgoing packets");
                self.send_handshake_init(peer_ref)?;
                Ok(false)
            },
            Decision::Drop => {
                let _ = self.outgoing_rx.poll();
                Ok(true)
            },
            Decision::Wait => {
                Ok(false)
            }
        }
    }
}

impl Future for PeerServer {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Handle pending state-changing timers
        loop {
            match self.timer.poll() {
                Ok(Async::Ready(Some(message))) => {
                    let _ = self.handle_timer(message).map_err(|e| debug!("TIMER: {}", e));
                },
                Ok(Async::NotReady) => break,
                Ok(Async::Ready(None)) | Err(_) => return Err(()),
            }
        }

        // Handle UDP packets from the outside world
        loop {
            match self.udp_stream.poll() {
                Ok(Async::Ready(Some((addr, packet)))) => {
                    let _ = self.handle_incoming_packet(addr, &packet).map_err(|e| warn!("UDP ERR: {:?}", e));
                },
                Ok(Async::NotReady) => break,
                Ok(Async::Ready(None)) | Err(_) => return Err(()),
            }
        }

        // Handle packets coming from the local tunnel
        loop {
            match self.peek_from_tun_and_handle().map_err(|e| { warn!("TUN ERR: {:?}", e); e }) {
                Ok(false) | Err(_) => break,
                _ => {}
            }
        }

        Ok(Async::NotReady)
    }
}
