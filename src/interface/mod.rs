mod config;
mod grim_reaper;
pub mod peer_server;

use self::config::ConfigurationService;
use self::peer_server::PeerServer;
use router::Router;

use failure::{Error, err_msg};
use peer::Peer;
use std::io;
use std::rc::{Rc, Weak};
use std::cell::RefCell;
use std::collections::HashMap;
use types::{InterfaceInfo, PacketVec};

use rips_packets::ipv4::Ipv4Packet;

use futures::{Future, Stream, Sink, unsync};
use tokio_core::reactor::Core;
use tokio_utun::{UtunStream, UtunCodec};


pub fn trace_packet(header: &str, packet: &[u8]) {
    let packet = Ipv4Packet::new(packet);
    trace!("{} {:?}", header, packet);
}

pub type SharedPeer = Rc<RefCell<Peer>>;
pub type WeakSharedPeer = Weak<RefCell<Peer>>;
pub type SharedState = Rc<RefCell<State>>;

#[derive(Default)]
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

impl UtunCodec for VecUtunCodec {
    type In = PacketVec;
    type Out = PacketVec;

    fn decode(&mut self, buf: &[u8]) -> io::Result<Self::In> {
        Ok(buf[4..].into())
    }

    fn encode(&mut self, mut msg: Self::Out, buf: &mut Vec<u8>) {
        buf.append(&mut msg);
    }
}

impl Interface {
    pub fn new(name: &str) -> Self {
        let state = State::default();
        Interface {
            name: name.to_owned(),
            state: Rc::new(RefCell::new(state)),
        }
    }

    pub fn start(&mut self) -> Result<(), Error> {
        let mut core = Core::new()?;

        let (utun_tx, utun_rx) = unsync::mpsc::unbounded::<Vec<u8>>();

        let peer_server    = PeerServer::new(core.handle(), self.state.clone(), utun_tx.clone())?;
        let utun_stream    = UtunStream::connect(&self.name, &core.handle())?;
        let interface_name = utun_stream.name()?;
        let utun_stream    = utun_stream.framed(VecUtunCodec{});
        let config_server  = ConfigurationService::new(&interface_name, &self.state, peer_server.tx(), &core.handle())?.map_err(|_|());
        self.name = interface_name;

        let (utun_writer, utun_reader) = utun_stream.split();

        let utun_read_fut = peer_server.tunnel_tx()
            .sink_map_err(|e| -> Error { e.into() })
            .send_all(utun_reader.map_err(|e| -> Error { e.into() }))
            .map_err(|e| { warn!("utun read error: {:?}", e); () });

        let utun_write_fut = utun_writer
            .sink_map_err(|e| -> Error { e.into() })
            .send_all(utun_rx.map_err(|()| -> Error { err_msg("utun rx failure") }))
            .map_err(|e| { warn!("utun write error: {:?}", e); () });

        let utun_futs = utun_write_fut.join(utun_read_fut);

        let fut = peer_server
            .map_err(|e| error!("peer_server error: {:?}", e))
            .join(config_server.join(utun_futs));
        let _ = core.run(fut);

        info!("reactor finished.");
        Ok(())
    }
}
