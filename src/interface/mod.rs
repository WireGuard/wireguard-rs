mod config;

use self::config::{ConfigurationServiceManager, UpdateEvent, Command, ConfigurationCodec};
use base64;
use hex;
use byteorder::{ByteOrder, BigEndian, LittleEndian};
use snow::NoiseBuilder;
use protocol::Peer;
use std::io;
use std::rc::Rc;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use types::{InterfaceInfo};

use pnet::packet::ipv4::Ipv4Packet;

use futures::{Future, Stream, Sink, future, unsync, sync, stream};
use tokio_core::reactor::{Core, Handle};
use tokio_core::net::{UdpSocket, UdpCodec};
use tokio_utun::{UtunStream, UtunCodec};
use tokio_io::{AsyncRead};
use tokio_io::codec::{Framed, Encoder, Decoder};
use tokio_uds::{UnixListener};
use tokio_timer::{Interval, Timer};

fn debug_packet(header: &str, packet: &[u8]) {
    let packet = Ipv4Packet::new(packet);
    debug!("{} {:?}", header, packet);
}

pub struct Interface {
    name: String,
    info: Rc<RefCell<InterfaceInfo>>,
    peers: Rc<RefCell<HashMap<[u8; 32], Rc<RefCell<Peer>>>>>,
    ids: Rc<RefCell<HashMap<u32, Rc<RefCell<Peer>>>>>,
}

struct VecUdpCodec;
impl UdpCodec for VecUdpCodec {
    type In = (SocketAddr, Vec<u8>);
    type Out = (SocketAddr, Vec<u8>);

    fn decode(&mut self, src: &SocketAddr, buf: &[u8]) -> io::Result<Self::In> {
        Ok((*src, buf.to_vec()))
    }

    fn encode(&mut self, msg: Self::Out, buf: &mut Vec<u8>) -> SocketAddr {
        let (addr, mut data) = msg;
        buf.append(&mut data);
        addr
    }
}

struct VecUtunCodec;
#[allow(dead_code)]
enum UtunPacket {
    Inet4(Vec<u8>),
    Inet6(Vec<u8>),
}
impl UtunCodec for VecUtunCodec {
    type In = Vec<u8>;
    type Out = Vec<u8>;

    fn decode(&mut self, buf: &[u8]) -> io::Result<Self::In> {
        debug!("utun packet type {}", buf[3]);
        Ok(buf[4..].to_vec())
    }

    fn encode(&mut self, mut msg: Self::Out, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&[0u8, 0, 0, 2]);
        buf.append(&mut msg);
    }
}

impl Interface {
    pub fn new(name: &str) -> Self {
        let info = Rc::new(RefCell::new(InterfaceInfo::default()));
        let peers = Rc::new(RefCell::new(HashMap::new()));
        let ids = Rc::new(RefCell::new(HashMap::new()));
        let _config_service = ConfigurationServiceManager::new(name);
        Interface {
            name: name.to_owned(),
            info,
            peers,
            ids,
        }
    }

    pub fn start(&mut self) {
        let mut core = Core::new().unwrap();

        let (utun_tx, utun_rx) = unsync::mpsc::channel::<Vec<u8>>(1024);
        let udp_socket = UdpSocket::bind(&([0,0,0,0], 0).into(), &core.handle()).unwrap();
        let (tx, rx) = unsync::mpsc::channel::<(SocketAddr, Vec<u8>)>(1024);
        let (udp_writer, udp_reader) = udp_socket.framed(VecUdpCodec{}).split();
        let udp_read_fut = udp_reader.for_each({
            let ids_ref = self.ids.clone();
            let handle = core.handle();
            let tx = tx.clone();
            let interface_info = self.info.clone();
            move |(_socket_addr, packet)| {
                debug!("got a UDP packet of length {}, packet type {}", packet.len(), packet[0]);
                match packet[0] {
                    1 => {
                        info!("got handshake initialization.");
                    },
                    2 => {
                        let their_index = LittleEndian::read_u32(&packet[4..]);
                        let our_index = LittleEndian::read_u32(&packet[8..]);
                        let mut ids = ids_ref.borrow_mut();
                        let peer_ref = ids.get(&our_index).unwrap().clone();
                        let mut peer = peer_ref.borrow_mut();
                        peer.sessions.next.as_mut().unwrap().their_index = their_index;
                        let payload_len = peer.next_noise().expect("pending noise session")
                            .read_message(&packet[12..60], &mut []).unwrap();
                        assert!(payload_len == 0);
                        peer.ratchet_session().unwrap();
                        info!("got handshake response, ratcheted session.");
                        let tx = tx.clone();

                        let interface_info = interface_info.borrow();
                        let noise = NoiseBuilder::new("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
                            .local_private_key(&interface_info.private_key.expect("no private key!"))
                            .remote_public_key(&peer.info.pub_key)
                            .prologue("WireGuard v1 zx2c4 Jason@zx2c4.com".as_bytes())
                            .psk(2, &peer.info.psk.expect("no psk!"))
                            .build_initiator().unwrap();
                        peer.set_next_session(noise.into());

                        let _ = ids.insert(peer.our_next_index().unwrap(), peer_ref.clone());

                        let init_packet = peer.get_handshake_packet();
                        let endpoint = peer.info.endpoint.unwrap().clone();

                        let timer = Timer::default();
                        let sleep = timer.sleep(Duration::from_secs(120));
                        let boop = sleep.and_then({
                            let handle = handle.clone();
                            let peer_ref = peer_ref.clone();
                            let interface_info = interface_info.clone();
                            move |_| {
                                info!("sending rekey!");
                                handle.spawn(tx.clone().send((endpoint, init_packet))
                                    .map(|_| ())
                                    .map_err(|_| ()));
                                Ok(())
                            }
                        }).map_err(|_|());
                        handle.spawn(boop);
                    },
                    4 => {
                        let our_index_received = LittleEndian::read_u32(&packet[4..]);
                        let nonce = LittleEndian::read_u64(&packet[8..]);

                        let mut raw_packet = [0u8; 1500];
                        let ids = ids_ref.borrow();
                        let lookup = ids.get(&our_index_received);
                        if let Some(ref peer) = lookup {
                            let mut peer = peer.borrow_mut();
                            // info!("retrieved peer with pubkey {}", base64::encode(&peer.pubkey));
                            // info!("ok going to try to decrypt");

                            peer.rx_bytes += packet.len();
                            let noise = peer.current_noise().expect("current noise session");
                            noise.set_receiving_nonce(nonce).unwrap();
                            let payload_len = noise.read_message(&packet[16..], &mut raw_packet).unwrap();
                            debug_packet("received TRANSPORT: ", &raw_packet[..payload_len]);
                            handle.spawn(utun_tx.clone().send(raw_packet[..payload_len].to_owned())
                                .map(|_| ())
                                .map_err(|_| ()));
                        }
                    },
                    _ => unimplemented!()
                }
                Ok(())
            }
        }).map_err(|_| ());

        let udp_write_fut = udp_writer.sink_map_err(|_| ()).send_all(
            rx.map(|(addr, packet)| {
                debug!("sending encrypted UDP packet");
                (addr, packet)
            }).map_err(|_| ())).map_err(|_| ());

        let utun_stream = UtunStream::connect(&self.name, &core.handle()).unwrap().framed(VecUtunCodec{});
        let (utun_writer, utun_reader) = utun_stream.split();
        let utun_fut = utun_reader.for_each({
            let ids = self.ids.clone();
            let utun_handle = core.handle();
            let udp_tx = tx.clone();
            move |packet| {
                debug_packet("received UTUN packet: ", &packet);
                let mut ping_packet = [0u8; 1500];
                let ids = ids.borrow();
                let (_key, peer) = ids.iter().next().unwrap(); // TODO destination IP peer lookup
                let mut peer = peer.borrow_mut();
                ping_packet[0] = 4;
                let their_index = peer.their_current_index().expect("no current index for them");
                let endpoint = peer.info.endpoint.unwrap();
                peer.tx_bytes += packet.len();
                let noise = peer.current_noise().expect("current noise session");
                LittleEndian::write_u32(&mut ping_packet[4..], their_index);
                LittleEndian::write_u64(&mut ping_packet[8..], noise.sending_nonce().unwrap());
                let len = noise.write_message(&packet, &mut ping_packet[16..]).expect("failed to encrypt outgoing UDP packet");
                utun_handle.spawn(udp_tx.clone().send((endpoint, ping_packet[..(16+len)].to_owned()))
                    .map(|_| ())
                    .map_err(|_| ()));
                Ok(())
            }
        }).map_err(|_| ());

        let utun_write_fut = utun_writer.sink_map_err(|_| ()).send_all(
            utun_rx.map(|packet| {
                debug_packet("sending UTUN: ", &packet);
                packet
            }).map_err(|_| ())).map_err(|_| ());

        let handle = core.handle();
        let listener = UnixListener::bind(ConfigurationServiceManager::get_path(&self.name).unwrap(), &handle).unwrap();
        let (config_tx, config_rx) = sync::mpsc::channel::<UpdateEvent>(1024);
        let h = handle.clone();
        let config_server = listener.incoming().for_each({
            let config_tx = config_tx.clone();
            let info = self.info.clone();
            let peers = self.peers.clone();
            move |(stream, _)| {
                let (sink, stream) = stream.framed(ConfigurationCodec {}).split();
                debug!("UnixServer connection.");

                let handle = h.clone();
                let responses = stream.and_then({
                    let config_tx = config_tx.clone();
                    let info = info.clone();
                    let peers = peers.clone();
                    move |command| {
                        match command {
                            Command::Set(_version, items) => {
                                config_tx.clone().send_all(stream::iter_ok(items)).wait().unwrap();
                                future::ok("errno=0\nerrno=0\n\n".to_string())
                            },
                            Command::Get(_version) => {
                                let info = info.borrow();
                                let peers = peers.borrow();
                                let mut s = String::new();
                                if let Some(private_key) = info.private_key {
                                    s.push_str(&format!("private_key={}\n", hex::encode(private_key)));
                                }

                                for (_, peer) in peers.iter() {
                                    s.push_str(&peer.borrow().to_config_string());
                                }
                                future::ok(format!("{}errno=0\n\n", s))
                            }
                        }
                    }
                });

                let fut = sink.send_all(responses).map(|_| ()).map_err(|_| ());

                handle.spawn(fut);

                Ok(())
            }
        }).map_err(|_| ());

        let config_fut = config_rx.for_each({
            let tx = tx.clone();
            let handle = handle.clone();
            move |event| {
                let interface_info = self.info.clone();
                match event {
                    UpdateEvent::PrivateKey(private_key) => {
                        let mut interface_info = interface_info.borrow_mut();
                        interface_info.private_key = Some(private_key);
                        debug!("set new private key");
                    },
                    UpdateEvent::ListenPort(port) => {
                        let mut interface_info = interface_info.borrow_mut();
                        interface_info.listen_port = Some(port);
                        debug!("set new listen port");
                    },
                    UpdateEvent::UpdatePeer(info) => {
                        info!("added new peer: {}", info);
                        let interface_info = interface_info.borrow();
                        let mut noise = NoiseBuilder::new("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
                            .local_private_key(&interface_info.private_key.expect("no private key!"))
                            .remote_public_key(&info.pub_key)
                            .prologue("WireGuard v1 zx2c4 Jason@zx2c4.com".as_bytes())
                            .psk(2, &info.psk.expect("no psk!"))
                            .build_initiator().unwrap();

                        let mut peer = Peer::new(info.clone());
                        peer.set_next_session(noise.into());

                        let init_packet = peer.get_handshake_packet();
                        let our_index = peer.our_next_index().unwrap();
                        let peer = Rc::new(RefCell::new(peer));

                        let _ = self.ids.borrow_mut().insert(our_index, peer.clone());
                        let _ = self.peers.borrow_mut().insert(info.pub_key, peer);

                        handle.spawn(tx.clone().send((info.endpoint.unwrap(), init_packet))
                            .map(|_| ())
                            .map_err(|_| ()));
                    },
                    _ => unimplemented!()
                }

                future::ok(())
            }
        }).map_err(|_| ());

        core.run(utun_fut.join(utun_write_fut.join(udp_read_fut.join(udp_write_fut.join(config_fut.join(config_server)))))).unwrap();
    }
}
