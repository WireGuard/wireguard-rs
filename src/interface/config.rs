//! The configuration logic for userspace WireGuard.

// Dev notes:
// * Configuration service should use channels to report updates it receives over its interface.

use bytes::BytesMut;
use failure::{Error, err_msg};
use std::fs::{create_dir, remove_file};
use std::mem;
use std::iter::Iterator;
use std::path::{Path, PathBuf};
use std::str;
use types::PeerInfo;
use hex::FromHex;

use tokio_io::codec::{Encoder, Decoder};

#[derive(Debug)]
pub enum Command {
    Set(usize, Vec<UpdateEvent>),
    Get(usize)
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum UpdateEvent {
    PrivateKey([u8; 32]),
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
            (true, true) => events.push(UpdateEvent::RemovePeer(info.pub_key)),
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

pub struct ConfigurationServiceManager {
    interface_name: String,
}

impl ConfigurationServiceManager {
    pub fn new(interface_name: &str) -> Self {
        ConfigurationServiceManager {
            interface_name: interface_name.into(),
        }
    }

    pub fn get_path(&self) -> Result<PathBuf, Error> {
        let mut socket_path = Self::get_run_path().join("wireguard");

        if !socket_path.exists() {
            debug!("Creating socket path: {}", socket_path.display());
            create_dir(&socket_path)?;
        }
        debug!("Setting chmod 0700 of socket path: {}",
               socket_path.display());
        Self::chmod(&socket_path, 0o700)?;

        // Finish the socket path
        socket_path.push(&self.interface_name);
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

impl Drop for ConfigurationServiceManager {
    fn drop(&mut self) {
        let mut socket_path = Self::get_run_path().join("wireguard");
        socket_path.push(&self.interface_name);
        socket_path.set_extension("sock");
        if socket_path.exists() {
            info!("Removing socket on drop: {}", socket_path.display());
            let _ = remove_file(&socket_path);
        }
    }
}
