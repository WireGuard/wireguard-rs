mod config;
mod peer_server;

use self::config::{ConfigurationServiceManager, UpdateEvent, Command, ConfigurationCodec};
use self::peer_server::PeerServer;
use router::Router;

use base64;
use hex;
use failure::Error;
use protocol::Peer;
use std::io;
use std::rc::Rc;
use std::cell::RefCell;
use std::collections::HashMap;
use types::{InterfaceInfo};
use x25519_dalek as x25519;

use pnet::packet::ipv4::Ipv4Packet;

use futures::{Future, Stream, Sink, future, unsync, sync, stream};
use tokio_core::reactor::Core;
use tokio_utun::{UtunStream, UtunCodec};
use tokio_io::{AsyncRead};
use tokio_uds::{UnixListener};


pub fn trace_packet(header: &str, packet: &[u8]) {
    let packet = Ipv4Packet::new(packet);
    trace!("{} {:?}", header, packet);
}

pub type SharedPeer = Rc<RefCell<Peer>>;
pub type SharedState = Rc<RefCell<State>>;

pub struct State {
    pubkey_map: HashMap<[u8; 32], SharedPeer>,
    index_map: HashMap<u32, SharedPeer>,
    router: Router,
    interface_info: InterfaceInfo,
}

pub struct Interface {
    name: String,
    state: SharedState,
}

struct VecUtunCodec;
pub enum UtunPacket {
    Inet4(Vec<u8>),
    Inet6(Vec<u8>),
}

impl UtunPacket {
    pub fn payload(&self) -> &[u8] {
        match self {
            &UtunPacket::Inet4(ref payload) => &payload,
            &UtunPacket::Inet6(ref payload) => &payload,
        }
    }

    pub fn from(raw_packet: Vec<u8>) -> Result<UtunPacket, Error> {
        match raw_packet[0] >> 4 {
            4 => Ok(UtunPacket::Inet4(raw_packet)),
            6 => Ok(UtunPacket::Inet6(raw_packet)),
            _ => bail!("unrecognized IP version")
        }
    }
}

impl UtunCodec for VecUtunCodec {
    type In = UtunPacket;
    type Out = UtunPacket;

    fn decode(&mut self, buf: &[u8]) -> io::Result<Self::In> {
        trace!("utun packet type {}", buf[3]);
        match buf[3] {
            0x02 => Ok(UtunPacket::Inet4(buf[4..].to_vec())),
            0x1e => Ok(UtunPacket::Inet6(buf[4..].to_vec())),
            _ => Err(io::ErrorKind::InvalidData.into())
        }
    }

    fn encode(&mut self, msg: Self::Out, buf: &mut Vec<u8>) {
        match msg {
            UtunPacket::Inet4(mut packet) => {
                buf.extend_from_slice(&[0x00u8, 0x00, 0x00, 0x02]);
                buf.append(&mut packet);
            },
            UtunPacket::Inet6(mut packet) => {
                buf.extend_from_slice(&[0x00u8, 0x00, 0x00, 0x1e]);
                buf.append(&mut packet);
            }
        }
    }
}

impl Interface {
    pub fn new(name: &str) -> Self {
        let state = State {
            pubkey_map: HashMap::new(),
            index_map: HashMap::new(),
            router: Router::new(),
            interface_info: InterfaceInfo::default(),
        };
        Interface {
            name: name.to_owned(),
            state: Rc::new(RefCell::new(state)),
        }
    }

    pub fn start(&mut self) {
        let mut core = Core::new().unwrap();

        let (utun_tx, utun_rx) = unsync::mpsc::channel::<UtunPacket>(1024);

        let peer_server = PeerServer::bind(core.handle(), self.state.clone(), utun_tx.clone()).unwrap();

        let utun_stream = UtunStream::connect(&self.name, &core.handle()).unwrap().framed(VecUtunCodec{});
        let (utun_writer, utun_reader) = utun_stream.split();
        let utun_read_fut = peer_server.tx()
            .sink_map_err(|_| ())
            .send_all(utun_reader.map_err(|_|()))
            .map_err(|_|());
        let utun_write_fut = utun_writer
            .sink_map_err(|_| ())
            .send_all(utun_rx.map_err(|_| ()))
            .map_err(|_| ());
        let utun_fut = utun_write_fut.join(utun_read_fut);

        let config_manager = ConfigurationServiceManager::new(&self.name);
        let handle = core.handle();
        let listener = UnixListener::bind(config_manager.get_path().unwrap(), &handle).unwrap();
        let (config_tx, config_rx) = sync::mpsc::channel::<UpdateEvent>(1024);
        let h = handle.clone();
        let config_server = listener.incoming().for_each({
            let config_tx = config_tx.clone();
            let state = self.state.clone();
            move |(stream, _)| {
                let (sink, stream) = stream.framed(ConfigurationCodec {}).split();
                trace!("UnixServer connection.");

                let handle = h.clone();
                let responses = stream.and_then({
                    let config_tx = config_tx.clone();
                    let state = state.clone();
                    move |command| {
                        let state = state.borrow();
                        match command {
                            Command::Set(_version, items) => {
                                config_tx.clone().send_all(stream::iter_ok(items)).wait().unwrap();
                                future::ok("errno=0\nerrno=0\n\n".to_string())
                            },
                            Command::Get(_version) => {
                                let info = &state.interface_info;
                                let peers = &state.pubkey_map;
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
            let tx = peer_server.udp_tx().clone();
            let handle = handle.clone();
            let state = self.state.clone();
            move |event| {
                let mut state = state.borrow_mut();
                match event {
                    UpdateEvent::PrivateKey(private_key) => {
                        let pub_key = x25519::generate_public(&private_key);
                        info!("set pubkey: {}", base64::encode(pub_key.as_bytes()));
                        state.interface_info.private_key = Some(private_key);
                        state.interface_info.pub_key = Some(*pub_key.as_bytes());
                        debug!("set new private key.");
                    },
                    UpdateEvent::ListenPort(port) => {
                        state.interface_info.listen_port = Some(port);
                        info!("set listen port: {}", port);
                    },
                    UpdateEvent::UpdatePeer(info) => {
                        info!("added new peer: {}", info);

                        let mut peer = Peer::new(info.clone());
                        let private_key = &state.interface_info.private_key.expect("no private key!");
                        let (init_packet, our_index) = peer.initiate_new_session(private_key).expect("initiate_new_session");

                        let peer = Rc::new(RefCell::new(peer));

                        state.router.add_allowed_ips(&info.allowed_ips, peer.clone());

                        let _ = state.index_map.insert(our_index, peer.clone());
                        let _ = state.pubkey_map.insert(info.pub_key, peer);

                        handle.spawn(tx.clone().send((info.endpoint.unwrap(), init_packet)).then(|_| Ok(())));
                        debug!("sent handshake packet to new peer");
                    },
                    UpdateEvent::RemovePeer(_pub_key) => {
                        warn!("RemovePeer event not yet handled");
                    },
                    _ => warn!("unhandled UpdateEvent received")
                }

                future::ok(())
            }
        }).map_err(|e| { warn!("error {:?}", e); () });

        core.run(peer_server.join(utun_fut.join(config_fut.join(config_server)))).unwrap();
    }
}
