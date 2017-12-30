use super::{SharedState, SharedPeer, debug_packet};

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use byteorder::{ByteOrder, BigEndian, LittleEndian};
use futures::{Async, Future, Stream, Sink, Poll, future, unsync, sync, stream};
use tokio_core::net::{UdpSocket, UdpCodec, UdpFramed};
use tokio_core::reactor::Handle;
use tokio_io::codec::Framed;
use tokio_timer::{Interval, Timer};
use snow::NoiseBuilder;


pub type PeerServerMessage = (SocketAddr, Vec<u8>);
struct VecUdpCodec;
impl UdpCodec for VecUdpCodec {
    type In = PeerServerMessage;
    type Out = PeerServerMessage;

    fn decode(&mut self, src: &SocketAddr, buf: &[u8]) -> io::Result<Self::In> {
        Ok((*src, buf.to_vec()))
    }

    fn encode(&mut self, msg: Self::Out, buf: &mut Vec<u8>) -> SocketAddr {
        let (addr, mut data) = msg;
        buf.append(&mut data);
        addr
    }
}


pub struct PeerServer {
    handle: Handle,
    shared_state: SharedState,
    udp_stream: stream::SplitStream<UdpFramed<VecUdpCodec>>,
    rx: unsync::mpsc::Receiver<Vec<u8>>,
    udp_tx: unsync::mpsc::Sender<(SocketAddr, Vec<u8>)>,
    tunnel_tx: unsync::mpsc::Sender<Vec<u8>>,
    pub tx: unsync::mpsc::Sender<Vec<u8>>,
}

impl PeerServer {
    pub fn bind(handle: Handle, shared_state: SharedState, tunnel_tx: unsync::mpsc::Sender<Vec<u8>>) -> Self {
        let socket = UdpSocket::bind(&([0,0,0,0], 0).into(), &handle.clone()).unwrap();
        let (udp_sink, udp_stream) = socket.framed(VecUdpCodec{}).split();
        let (udp_tx, udp_rx) = unsync::mpsc::channel::<(SocketAddr, Vec<u8>)>(1024);
        let (tx, rx) = unsync::mpsc::channel::<Vec<u8>>(1024);

        let udp_write_passthrough = udp_sink.sink_map_err(|_| ()).send_all(
            udp_rx.map(|(addr, packet)| {
                debug_packet("sending UDP: ", &packet);
                (addr, packet)
            }).map_err(|_| ()))
            .then(|_| Ok(()));
        handle.spawn(udp_write_passthrough);

        PeerServer {
            handle, shared_state, udp_stream, udp_tx, tunnel_tx, tx, rx
        }
    }

    pub fn tx(&self) -> unsync::mpsc::Sender<Vec<u8>> {
        self.tx.clone()
    }

    pub fn udp_tx(&self) -> unsync::mpsc::Sender<(SocketAddr, Vec<u8>)> {
        self.udp_tx.clone()
    }

    fn handle_incoming_packet(&mut self, addr: SocketAddr, packet: Vec<u8>) {
        debug!("got a UDP packet of length {}, packet type {}", packet.len(), packet[0]);
        let mut state = self.shared_state.borrow_mut();
        match packet[0] {
            1 => {
                info!("got handshake initialization.");
            },
            2 => {
                let their_index = LittleEndian::read_u32(&packet[4..]);
                let our_index = LittleEndian::read_u32(&packet[8..]);
                let peer_ref = state.index_map.get(&our_index).unwrap().clone();
                let mut peer = peer_ref.borrow_mut();
                peer.sessions.next.as_mut().unwrap().their_index = their_index;
                let payload_len = peer.next_noise().expect("pending noise session")
                    .read_message(&packet[12..60], &mut []).unwrap();
                assert!(payload_len == 0);
                peer.ratchet_session().unwrap();
                info!("got handshake response, ratcheted session.");

                let noise = NoiseBuilder::new("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
                    .local_private_key(&state.interface_info.private_key.expect("no private key!"))
                    .remote_public_key(&peer.info.pub_key)
                    .prologue("WireGuard v1 zx2c4 Jason@zx2c4.com".as_bytes())
                    .psk(2, &peer.info.psk.expect("no psk!"))
                    .build_initiator().unwrap();
                peer.set_next_session(noise.into());

                let _ = state.index_map.insert(peer.our_next_index().unwrap(), peer_ref.clone());

                let init_packet = peer.get_handshake_packet();
                let endpoint = peer.info.endpoint.unwrap().clone();

                let timer = Timer::default();
                let sleep = timer.sleep(Duration::from_secs(120));
                let boop = sleep.and_then({
                    let handle = self.handle.clone();
                    let tx = self.udp_tx.clone();
                    let peer_ref = peer_ref.clone();
                    move |_| {
                        info!("sending rekey!");
                        handle.spawn(tx.clone().send((endpoint, init_packet))
                            .map(|_| ())
                            .map_err(|_| ()));
                        Ok(())
                    }
                }).map_err(|_|());
                self.handle.spawn(boop);
            },
            4 => {
                let our_index_received = LittleEndian::read_u32(&packet[4..]);
                let nonce = LittleEndian::read_u64(&packet[8..]);

                let mut raw_packet = [0u8; 1500];
                let lookup = state.index_map.get(&our_index_received);
                if let Some(ref peer) = lookup {
                    let mut peer = peer.borrow_mut();

                    peer.rx_bytes += packet.len();
                    let noise = peer.current_noise().expect("current noise session");
                    noise.set_receiving_nonce(nonce).unwrap();
                    let payload_len = noise.read_message(&packet[16..], &mut raw_packet).unwrap();
                    debug_packet("received TRANSPORT: ", &raw_packet[..payload_len]);
                    self.handle.spawn(self.tunnel_tx.clone().send(raw_packet[..payload_len].to_owned())
                        .map(|_| ())
                        .map_err(|_| ()));
                }
            },
            _ => unimplemented!()
        }
    }

    fn handle_outgoing_packet(&mut self, packet: Vec<u8>) {
        debug!("handle_outgoing_packet()");

    }
}

impl Future for PeerServer {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Handle UDP packets from the outside world
        loop {
            match self.udp_stream.poll() {
                Ok(Async::Ready(Some((addr, packet)))) => self.handle_incoming_packet(addr, packet),
                Ok(Async::NotReady) => break,
                Ok(Async::Ready(None)) | Err(_) => return Err(()),
            }
        }

        // Handle packets coming from the local tunnel
        loop {
            match self.rx.poll() {
                Ok(Async::Ready(Some(packet))) => self.handle_outgoing_packet(packet),
                Ok(Async::NotReady) => break,
                Ok(Async::Ready(None)) | Err(_) => return Err(()),
            }
        }

        Ok(Async::NotReady)
    }
}
