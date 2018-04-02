//! The configuration logic for userspace WireGuard.

// Dev notes:
// * Configuration service should use channels to report updates it receives over its interface.

use base64;
use bytes::BytesMut;
use failure::{Error, err_msg};
use futures::{Async, Future, Poll, Stream, Sink, future, stream, unsync::mpsc};
use hex;
use interface::{SharedState, State};
use interface::grim_reaper::GrimReaper;
use peer::Peer;
use std::{cell::RefCell, iter::Iterator, rc::Rc, mem, str};
use std::fs::{create_dir, remove_file};
use std::path::{Path, PathBuf};
use tokio_core::reactor::Handle;
use types::PeerInfo;
use hex::FromHex;
use x25519_dalek as x25519;

use tokio_io::{AsyncRead, codec::{Encoder, Decoder}};
use tokio_uds::UnixListener;

#[derive(Debug)]
pub enum Command {
    Set(usize, Vec<UpdateEvent>),
    Get(usize)
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum UpdateEvent {
    PrivateKey([u8; 32]),
    Fwmark(u32),
    ListenPort(u16),
    UpdatePeer(PeerInfo, bool),
    RemovePeer([u8; 32]),
    RemoveAllPeers,
}

impl UpdateEvent {
    fn from(items: Vec<(String, String)>) -> Result<Vec<UpdateEvent>, Error> {
        let mut events              = vec![];
        let mut pending_peer        = false;
        let mut remove_pending_peer = false;
        let mut replace_allowed_ips = false;
        let mut info                = PeerInfo::default();

        for (key, value) in items {
            match key.as_ref() {
                "private_key"                   => { events.push(UpdateEvent::PrivateKey(<[u8; 32]>::from_hex(&value)?)); },
                "listen_port"                   => { events.push(UpdateEvent::ListenPort(value.parse()?)); },
                "fwmark"                        => { events.push(UpdateEvent::Fwmark(value.parse()?)); },
                "replace_peers"                 => { events.push(UpdateEvent::RemoveAllPeers); },
                "preshared_key"                 => { info.psk       = Some(<[u8; 32]>::from_hex(&value)?); },
                "persistent_keepalive_interval" => { info.keepalive = Some(value.parse()?); },
                "endpoint"                      => { info.endpoint  = Some(value.parse()?); },
                "replace_allowed_ips"           => { replace_allowed_ips = true; },
                "remove"                        => { remove_pending_peer = true; },
                "public_key" => {
                    let peer_info = mem::replace(&mut info, PeerInfo::default());
                    match (pending_peer, remove_pending_peer) {
                        (true, true ) => events.push(UpdateEvent::RemovePeer(peer_info.pub_key)),
                        (true, false) => events.push(UpdateEvent::UpdatePeer(peer_info, replace_allowed_ips)),
                        _ => {}
                    }
                    info.pub_key = <[u8; 32]>::from_hex(&value)?;
                    pending_peer = true;
                    remove_pending_peer = false;
                    replace_allowed_ips = false;
                },
                "allowed_ip" => {
                    let (ip, cidr) = value.split_at(value.find('/').ok_or_else(|| err_msg("ip/cidr format error"))?);
                    info.allowed_ips.push((ip.parse()?, (&cidr[1..]).parse()?))
                },
                _ => { warn!("unrecognized configuration pair: {}={}", key, value)}
            }
        }

        // "flush" the final peer if there is one
        match (pending_peer, remove_pending_peer) {
            (true, true ) => events.push(UpdateEvent::RemovePeer(info.pub_key)),
            (true, false) => events.push(UpdateEvent::UpdatePeer(info, replace_allowed_ips)),
            _ => {}
        }
        trace!("events {:?}", events);
        Ok(events)
    }
}

pub struct ConfigurationCodec;

impl Decoder for ConfigurationCodec {
    type Item = Command;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Determine we have a full command ready for parsing.
        let mut items = Vec::new();
        let utf8 = String::from_utf8(buf.to_vec()).unwrap();
        let mut data_iter = utf8.split("\n\n");
        let blob = data_iter.next().unwrap();
        if data_iter.next().is_none() {
            return Ok(None)
        }

        // Parse the key-value pairs into something more usable
        for line in blob.split('\n') {
            let mut entry = line.split('=');
            items.push((entry.next().unwrap().to_owned(), entry.next().unwrap().to_owned()));
        }
        buf.split_to(blob.len()+1);

        let (ref cmd, ref version) = items.remove(0);
        let command = match cmd.as_str() {
            "get" => Command::Get(version.parse()?),
            "set" => Command::Set(version.parse()?, UpdateEvent::from(items)?),
            _ => bail!("invalid command")
        };

        Ok(Some(command))
    }
}

impl Encoder for ConfigurationCodec {
    type Item = String;
    type Error = Error;

    fn encode(&mut self, msg: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        buf.extend(msg.as_bytes());
        buf.extend(b"\n\n");
        Ok(())
    }
}

pub struct ConfigurationService {
    interface_name: String,
    config_server: Box<Future<Item = (), Error = ()>>,
    reaper: Box<Future<Item = (), Error = ()>>,
    rx: mpsc::Receiver<UpdateEvent>,
}

impl ConfigurationService {
    pub fn new(interface_name: &str, state: &SharedState, handle: &Handle) -> Result<Self, Error> {
        let config_path = Self::get_path(interface_name).unwrap();
        let listener    = UnixListener::bind(config_path.clone(), handle).unwrap();
        let (tx, rx)    = mpsc::channel::<UpdateEvent>(1024);

        // TODO only listen for own socket, verify behavior from `notify` crate
        let reaper = GrimReaper::spawn(handle, config_path.parent().unwrap()).unwrap();

        let config_server = listener.incoming().for_each({
            let handle = handle.clone();
            let tx = tx.clone();
            let state = state.clone();
            move |(stream, _)| {
                let (sink, stream) = stream.framed(ConfigurationCodec {}).split();
                trace!("UnixServer connection.");

                let handle = handle.clone();
                let responses = stream.and_then({
                    let tx = tx.clone();
                    let state = state.clone();
                    move |command| {
                        let mut state = state.borrow_mut();
                        match command {
                            Command::Set(_version, items) => {
                                for item in &items {
                                    if Self::handle_update(&mut state, item).is_err() {
                                        return future::ok("errno=1\nerrno=1\n\n".into());
                                    }
                                }
                                tx.clone().send_all(stream::iter_ok(items)).wait().unwrap();
                                future::ok("errno=0\nerrno=0\n\n".into())
                            },
                            Command::Get(_version) => {
                                let info = &state.interface_info;
                                let peers = &state.pubkey_map;
                                let mut s = String::new();
                                if let Some(private_key) = info.private_key {
                                    s.push_str(&format!("private_key={}\n", hex::encode(private_key)));
                                }
                                if let Some(port) = info.listen_port {
                                    s.push_str(&format!("listen_port={}\n", port));
                                }
                                for (_, peer) in peers.iter() {
                                    s.push_str(&peer.borrow().to_config_string());
                                }
                                future::ok(format!("{}errno=0\n\n", s))
                            }
                        }
                    }
                });

                let fut = sink.send_all(responses)
                    .map(|_| ())
                    .map_err(|_| ());

                handle.spawn(fut);

                Ok(())
            }
        }).map_err(|_| ());

        Ok(ConfigurationService {
            interface_name: interface_name.to_owned(),
            config_server: Box::new(config_server),
            reaper: Box::new(reaper),
            rx
        })
    }

    fn clear_peer_refs(state: &mut State, peer: &Peer) {
        for index in peer.get_mapped_indices() {
            let _ = state.index_map.remove(&index);
        }
        state.router.remove_allowed_ips(&peer.info.allowed_ips);
    }

    pub fn handle_update(state: &mut State, event: &UpdateEvent) -> Result<(), Error> {
        match *event {
            UpdateEvent::PrivateKey(private_key) => {
                let pub_key = x25519::generate_public(&private_key);
                state.interface_info.private_key = Some(private_key);
                state.interface_info.pub_key     = Some(*pub_key.as_bytes());
                debug!("set new private key (pub: {}).", base64::encode(pub_key.as_bytes()));

                if let Some(peer_ref) = state.pubkey_map.remove(&*pub_key.as_bytes()) {
                    Self::clear_peer_refs(state, &peer_ref.borrow());
                    debug!("removed self from peers");
                }
            },
            UpdateEvent::ListenPort(port) => {
                state.interface_info.listen_port = Some(port);
                debug!("set listen port: {}", port);
            },
            UpdateEvent::Fwmark(mark) => {
                state.interface_info.fwmark = Some(mark);
                debug!("set fwmark: {}", mark);
            }
            UpdateEvent::UpdatePeer(ref info, replace_allowed_ips) => {
                let existing_peer = state.pubkey_map.get(&info.pub_key).cloned();
                if let Some(peer_ref) = existing_peer {
                    debug!("updating peer: {}", info);
                    let mut peer = peer_ref.borrow_mut();
                    let mut info = info.clone();
                    if replace_allowed_ips {
                        state.router.remove_allowed_ips(&peer.info.allowed_ips);
                    } else {
                        info.allowed_ips.extend_from_slice(&peer.info.allowed_ips);
                    }
                    info.endpoint  = info.endpoint.or(peer.info.endpoint);
                    info.keepalive = info.keepalive.or(peer.info.keepalive);
                    state.router.add_allowed_ips(&info.allowed_ips, &peer_ref);
                    peer.info = info;
                } else {
                    if let Some(pub_key) = state.interface_info.pub_key {
                        if pub_key == info.pub_key {
                            debug!("ignoring self-peer add");
                            return Ok(())
                        }
                    }
                    debug!("adding new peer: {}", info);
                    let mut peer = Peer::new(info.clone());
                    let peer_ref = Rc::new(RefCell::new(peer));
                    let _ = state.pubkey_map.insert(info.pub_key, peer_ref.clone());
                    state.router.add_allowed_ips(&info.allowed_ips, &peer_ref);
                };
            },
            UpdateEvent::RemoveAllPeers => {
                state.pubkey_map.clear();
                state.index_map.clear();
                state.router.clear();
            },
            UpdateEvent::RemovePeer(pub_key) => {
                let peer_ref = state.pubkey_map.remove(&pub_key)
                    .ok_or_else(|| err_msg("trying to remove nonexistent peer"))?;
                Self::clear_peer_refs(state, &peer_ref.borrow());
            },
        }
        Ok(())
    }

    pub fn get_path(interface_name: &str) -> Result<PathBuf, Error> {
        let mut socket_path = Self::get_run_path().join("wireguard");

        if !socket_path.exists() {
            debug!("Creating socket path: {}", socket_path.display());
            create_dir(&socket_path)?;
        }
        debug!("Setting chmod 0700 of socket path: {}",
               socket_path.display());
        Self::chmod(&socket_path, 0o700)?;

        // Finish the socket path
        socket_path.push(interface_name);
        socket_path.set_extension("sock");
        if socket_path.exists() {
            debug!("Removing existing socket: {}", socket_path.display());
            remove_file(&socket_path)?;
        }

        Ok(socket_path)
    }

    #[cfg(unix)]
    fn chmod(path: &Path, perms: u32) -> Result<(), Error> {
        use std::os::unix::prelude::PermissionsExt;
        use std::fs::{set_permissions, Permissions};
        set_permissions(path, Permissions::from_mode(perms))?;
        Ok(())
    }

    #[cfg(windows)]
    fn chmod(_path: &Path, _perms: u32) -> Result<(), Error> {
        Ok(())
    }

    /// Returns the path where the socket and pid file will be stored
    pub fn get_run_path() -> PathBuf {
        if Path::new("/run").exists() {
            PathBuf::from("/run")
        } else {
            PathBuf::from("/var").join("run")
        }
    }
}

impl Stream for ConfigurationService {
    type Item  = UpdateEvent;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.config_server.poll() {
            Ok(Async::NotReady) => {},
            _ => return Err(err_msg("config_server broken")),

        }

        match self.reaper.poll() {
            Ok(Async::NotReady) => {},
            _ => {
                debug!("reaper triggered, closing ConfigurationService stream.");
                return Err(err_msg("reaper triggered, closing ConfigurationService stream."))
            },
        }

        match self.rx.poll() {
            Ok(Async::Ready(None)) | Err(_) => Err(err_msg("err in config rx channel")),
            Ok(Async::Ready(msg)) => Ok(Async::Ready(msg)),
            Ok(Async::NotReady)   => Ok(Async::NotReady)
        }
    }
}

impl Drop for ConfigurationService {
    fn drop(&mut self) {
        let mut socket_path = Self::get_run_path().join("wireguard");
        socket_path.push(&self.interface_name);
        socket_path.set_extension("sock");
        if socket_path.exists() {
            debug!("Removing socket on drop: {}", socket_path.display());
            let _ = remove_file(&socket_path);
        }
    }
}
