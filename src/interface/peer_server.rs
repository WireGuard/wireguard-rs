use super::{SharedState, SharedPeer, UtunPacket, trace_packet};
use consts::{REKEY_AFTER_TIME, KEEPALIVE_TIMEOUT, MAX_CONTENT_SIZE, TRANSPORT_HEADER_SIZE, TRANSPORT_OVERHEAD};
use protocol::Session;
use noise::Noise;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use base64;
use byteorder::{ByteOrder, BigEndian, LittleEndian};
use failure::{Error, SyncFailure};
use futures::{self, Async, Future, Stream, Sink, Poll, future, unsync, sync, stream};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use socket2::{Socket, Domain, Type, SockAddr, Protocol};
use snow;
use tokio_core::net::{UdpSocket, UdpCodec, UdpFramed};
use tokio_core::reactor::Handle;
use tokio_io::codec::Framed;
use tokio_timer::{Interval, Timer};
use treebitmap::{IpLookupTable, IpLookupTableOps};


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
            v6addr => v6addr.clone()
        };
        addr.set_ip(mapped_ip);
        addr
    }
}

#[derive(Debug)]
pub enum TimerMessage {
    KeepAlive(SharedPeer, u32),
    Rekey(SharedPeer, u32),
}

pub struct PeerServer {
    handle: Handle,
    shared_state: SharedState,
    timer: Timer,
    udp_stream: stream::SplitStream<UdpFramed<VecUdpCodec>>,
    outgoing_tx: unsync::mpsc::Sender<UtunPacket>,
    outgoing_rx: futures::stream::Peekable<unsync::mpsc::Receiver<UtunPacket>>,
    timer_tx: unsync::mpsc::Sender<TimerMessage>,
    timer_rx: unsync::mpsc::Receiver<TimerMessage>,
    udp_tx: unsync::mpsc::Sender<(SocketAddr, Vec<u8>)>,
    tunnel_tx: unsync::mpsc::Sender<UtunPacket>,
}

impl PeerServer {
    pub fn bind(handle: Handle, shared_state: SharedState, tunnel_tx: unsync::mpsc::Sender<UtunPacket>) -> Result<Self, Error> {
        let socket = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp()))?;
        socket.set_only_v6(false)?;
        socket.set_nonblocking(true)?;
        socket.bind(&SocketAddr::from((Ipv6Addr::unspecified(), 0)).into())?;
        let socket = UdpSocket::from_socket(socket.into_udp_socket(), &handle.clone())?;
        let (udp_sink, udp_stream) = socket.framed(VecUdpCodec{}).split();
        let (timer_tx, timer_rx) = unsync::mpsc::channel::<TimerMessage>(1024);
        let (udp_tx, udp_rx) = unsync::mpsc::channel::<(SocketAddr, Vec<u8>)>(1024);
        let (outgoing_tx, outgoing_rx) = unsync::mpsc::channel::<UtunPacket>(1024);
        let outgoing_rx = outgoing_rx.peekable();
        let timer = Timer::default();

        let udp_write_passthrough = udp_sink.sink_map_err(|_| ()).send_all(
            udp_rx.map(|(addr, packet)| {
                trace!("sending UDP packet to {:?}", &addr);
                (addr, packet)
            }).map_err(|_| ()))
            .then(|_| Ok(()));
        handle.spawn(udp_write_passthrough);

        Ok(PeerServer {
            handle, shared_state, timer, udp_stream, udp_tx, tunnel_tx, timer_tx, timer_rx, outgoing_tx, outgoing_rx
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

    fn handle_incoming_packet(&mut self, addr: SocketAddr, packet: Vec<u8>) -> Result<(), Error> {
        debug!("got a UDP packet from {:?} of length {}, packet type {}", &addr, packet.len(), packet[0]);
        let mut state = self.shared_state.borrow_mut();
        match packet[0] {
            1 => {
                ensure!(packet.len() == 148, "handshake init packet length is incorrect");
                {
                    let pubkey = state.interface_info.pub_key.as_ref()
                        .ok_or_else(|| format_err!("must have local interface key"))?;
                    let (mac_in, mac_out) = packet.split_at(116);
                    Noise::verify_mac1(pubkey, mac_in, &mac_out[..16])?;
                }

                info!("got handshake initiation request");

                let their_index = LittleEndian::read_u32(&packet[4..]);

                let mut noise = Noise::build_responder(
                    &state.interface_info.private_key.ok_or_else(|| format_err!("no private key!"))?)?;

                let mut timestamp = [0u8; 12];
                let len = noise.read_message(&packet[8..116], &mut timestamp)
                    .map_err(SyncFailure::new)?;
                ensure!(len == 12, "incorrect handshake payload length");

                let mut peer_ref = {
                    let their_pubkey = noise.get_remote_static().expect("must have remote static key");

                    debug!("their_pubkey: {}", base64::encode(&their_pubkey[..]));
                    state.pubkey_map.get(&their_pubkey[..])
                        .ok_or_else(|| format_err!("unknown peer pubkey"))?.clone()
                };
                let mut peer = peer_ref.borrow_mut();

                let (response, next_index) = peer.process_incoming_handshake(addr, their_index, timestamp.into(), noise)?;
                let _ = state.index_map.insert(next_index, peer_ref.clone());

                self.send_to_peer((addr, response));
                info!("sent handshake response, ratcheted session (index {}).", next_index);
            },
            2 => {
                ensure!(packet.len() == 92, "handshake resp packet length is incorrect");
                {
                    let pubkey = state.interface_info.pub_key.as_ref()
                        .ok_or_else(|| format_err!("must have local interface key"))?;
                    let (mac_in, mac_out) = packet.split_at(60);
                    Noise::verify_mac1(pubkey, mac_in, &mac_out[..16])?;
                }
                let our_index = LittleEndian::read_u32(&packet[8..]);
                let peer_ref  = state.index_map.get(&our_index)
                    .ok_or_else(|| format_err!("unknown our_index ({})", our_index))?
                    .clone();
                let mut peer = peer_ref.borrow_mut();
                let dead_index = peer.process_incoming_handshake_response(&packet)?;
                if let Some(index) = dead_index {
                    let _ = state.index_map.remove(&index);
                }
                info!("got handshake response, ratcheted session.");

                // TODO neither of these timers are to spec, but are simple functional placeholders
                let rekey_timer = self.timer.sleep(Duration::from_secs(REKEY_AFTER_TIME));
                let rekey_future = rekey_timer.map_err(|_|()).and_then({
                    let timer_tx = self.timer_tx.clone();
                    let peer_ref = peer_ref.clone();
                    move |_| {
                        timer_tx.clone().send(TimerMessage::Rekey(peer_ref, our_index))
                            .then(|_| Ok(()))
                    }
                }).then(|_| Ok(()));
                self.handle.spawn(rekey_future);

                let keepalive_interval = self.timer.interval(Duration::from_secs(KEEPALIVE_TIMEOUT));
                let keepalive_future = keepalive_interval.map_err(|_|()).for_each({
                    let timer_tx = self.timer_tx.clone();
                    let peer_ref = peer_ref.clone();
                    move |_| -> Box<Future<Item = _, Error = _>> {
                        if peer_ref.borrow().our_current_index().unwrap() != our_index {
                            debug!("cancelling old keepalive_timer");
                            Box::new(future::err(()))
                        } else {
                            Box::new(timer_tx.clone().send(TimerMessage::KeepAlive(peer_ref.clone(), our_index))
                                .then(|_| Ok(())))
                        }
                    }
                });
                self.handle.spawn(keepalive_future);
            },
            3 => {
                warn!("cookie messages not yet implemented.");
            }
            4 => {
                let our_index_received = LittleEndian::read_u32(&packet[4..]);
                let nonce = LittleEndian::read_u64(&packet[8..]);

                let peer_ref = state.index_map.get(&our_index_received)
                    .ok_or_else(|| format_err!("unknown our_index"))?
                    .clone();

                let (raw_packet, dead_index) = {
                    let mut peer = peer_ref.borrow_mut();
                    peer.handle_incoming_transport(our_index_received, nonce, addr, &packet[16..])?
                };

                if let Some(index) = dead_index {
                    let _ = state.index_map.remove(&index);
                }

                if raw_packet.len() == 0 {
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

                let private_key = &state.interface_info.private_key.expect("no private key!");
                let (init_packet, our_index) = peer.initiate_new_session(private_key).unwrap();
                let _ = state.index_map.insert(our_index, peer_ref.clone());

                let endpoint = peer.info.endpoint.ok_or_else(|| format_err!("no endpoint for peer"))?;

                self.send_to_peer((endpoint, init_packet));
                info!("sent rekey");
            },
            TimerMessage::KeepAlive(peer_ref, _our_index) => {
                let mut peer = peer_ref.borrow_mut();
                let mut packet = vec![0u8; TRANSPORT_OVERHEAD];
                packet[0] = 4;
                let their_index = peer.their_current_index().expect("no current index for them");
                let endpoint = peer.info.endpoint.unwrap();
                peer.tx_bytes += packet.len() as u64;
                let noise = peer.current_noise().expect("current noise session");
                LittleEndian::write_u32(&mut packet[4..], their_index);
                LittleEndian::write_u64(&mut packet[8..], noise.sending_nonce().unwrap());
                let _ = noise.write_message(&[], &mut packet[16..]).map_err(SyncFailure::new)?;
                self.send_to_peer((endpoint, packet));
                debug!("sent keepalive");
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

            ensure!(packet.payload().len() != 0 && packet.payload().len() < MAX_CONTENT_SIZE,
                "illegal packet size");

            trace_packet("received UTUN packet: ", packet.payload());
            let state = self.shared_state.borrow();
            let peer = state.router.route_to_peer(packet.payload()).ok_or_else(|| format_err!("no route to peer"))?;
            let mut peer = peer.borrow_mut();

            peer.handle_outgoing_transport(packet.payload())?
        };

        self.send_to_peer((endpoint, out_packet));
        let _ = self.outgoing_rx.poll(); // if we haven't short-circuited yet, take the packet out of the queue
        return Ok(true)
    }
}

impl Future for PeerServer {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Handle pending state-changing timers
        loop {
            match self.timer_rx.poll() {
                Ok(Async::Ready(Some(message))) => {
                    let _ = self.handle_timer(message).map_err(|e| warn!("TIMER ERR: {:?}", e));
                },
                Ok(Async::NotReady) => break,
                Ok(Async::Ready(None)) | Err(_) => return Err(()),
            }
        }

        // Handle UDP packets from the outside world
        loop {
            match self.udp_stream.poll() {
                Ok(Async::Ready(Some((addr, packet)))) => {
                    let _ = self.handle_incoming_packet(addr, packet).map_err(|e| warn!("UDP ERR: {:?}", e));
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
