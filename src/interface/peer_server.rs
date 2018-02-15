use super::{SharedState, UtunPacket, trace_packet};
use consts::{REKEY_TIMEOUT, REKEY_AFTER_TIME, KEEPALIVE_TIMEOUT, MAX_CONTENT_SIZE, TIMER_TICK_DURATION};
use protocol::{Peer, SessionType};
use noise::Noise;
use timer::{Timer, TimerMessage};

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Instant;

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

    pub fn udp_tx(&self) -> unsync::mpsc::Sender<(SocketAddr, Vec<u8>)> {
        self.udp_tx.clone()
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

                info!("got handshake initiation request (0x01)");

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
                info!("got handshake response (0x02)");

                let our_index = LittleEndian::read_u32(&packet[8..]);
                let peer_ref  = state.index_map.get(&our_index)
                    .ok_or_else(|| format_err!("unknown our_index ({})", our_index))?
                    .clone();
                let mut peer = peer_ref.borrow_mut();
                let dead_index = peer.process_incoming_handshake_response(packet)?;
                if let Some(index) = dead_index {
                    let _ = state.index_map.remove(&index);
                }
                info!("handshake response processed, current session now {}", our_index);

                // Start the timers for this new session
                self.timer.spawn_delayed(&self.handle,
                                         *REKEY_AFTER_TIME,
                                         TimerMessage::Rekey(peer_ref.clone(), our_index));

                self.timer.spawn_delayed(&self.handle,
                                         *KEEPALIVE_TIMEOUT,
                                         TimerMessage::KeepAlive(peer_ref.clone(), our_index));
            },
            3 => {
                warn!("cookie messages not yet implemented.");
            }
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

    fn handle_timer(&mut self, message: TimerMessage) -> Result<(), Error> {
        let mut state = self.shared_state.borrow_mut();
        match message {
            TimerMessage::Rekey(peer_ref, _our_index) => {
                let mut peer = peer_ref.borrow_mut();

                let now = Instant::now();
                if let Some(last_init) = peer.last_rekey_init {
                    if now.duration_since(last_init) < *REKEY_TIMEOUT {
                        debug!("too soon since last rekey attempt");
                    }
                }

                let private_key = &state.interface_info.private_key.expect("no private key!");
                let (init_packet, our_index) = peer.initiate_new_session(private_key).unwrap();
                let _ = state.index_map.insert(our_index, peer_ref.clone());

                let endpoint = peer.info.endpoint.ok_or_else(|| err_msg("no endpoint for peer"))?;

                self.send_to_peer((endpoint, init_packet));
                info!("sent rekey");
            },
            TimerMessage::KeepAlive(peer_ref, our_index) => {
                let mut peer = peer_ref.borrow_mut();
                {
                    let (session, session_type) = peer.find_session(our_index).ok_or_else(|| err_msg("missing session for timer"))?;
                    ensure!(session_type == SessionType::Current, "expired session for timer");

                    if let Some(last_sent) = session.last_sent {
                        let last_sent_packet = Instant::now().duration_since(last_sent);
                        if last_sent_packet < *KEEPALIVE_TIMEOUT {
                            self.timer.spawn_delayed(&self.handle,
                                                     *KEEPALIVE_TIMEOUT - last_sent_packet + *TIMER_TICK_DURATION,
                                                     TimerMessage::KeepAlive(peer_ref.clone(), our_index));
                            bail!("passive keepalive tick (waiting {:?})", *KEEPALIVE_TIMEOUT - last_sent_packet);
                        }
                    }
                }

                self.send_to_peer(peer.handle_outgoing_transport(&[])?);
                debug!("sent keepalive packet ({})", our_index);

                self.timer.spawn_delayed(&self.handle,
                                         *KEEPALIVE_TIMEOUT,
                                         TimerMessage::KeepAlive(peer_ref.clone(), our_index));
            }
        }
        Ok(())
    }

    // Just this way to avoid a double-mutable-borrow while peeking.
    fn peek_from_tun_and_handle(&mut self) -> Result<bool, Error> {
        let (endpoint, out_packet) = {
            let packet = match self.outgoing_rx.peek() {
                Ok(Async::Ready(Some(packet))) => packet,
                Ok(Async::NotReady) => return Ok(false),
                Ok(Async::Ready(None)) | Err(_) => bail!("channel failure"),
            };

            ensure!(!packet.payload().is_empty() && packet.payload().len() < MAX_CONTENT_SIZE,
                "illegal packet size");

            trace_packet("received UTUN packet: ", packet.payload());
            let state = self.shared_state.borrow();
            let peer = state.router.route_to_peer(packet.payload()).ok_or_else(|| err_msg("no route to peer"))?;
            let mut peer = peer.borrow_mut();

            peer.handle_outgoing_transport(packet.payload())?
        };

        self.send_to_peer((endpoint, out_packet));
        let _ = self.outgoing_rx.poll(); // if we haven't short-circuited yet, take the packet out of the queue
        Ok(true)
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
