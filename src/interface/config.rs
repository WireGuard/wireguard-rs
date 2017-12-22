//! The configuration logic for userspace WireGuard.

// Dev notes:
// * Configuration service should use channels to report updates it receives over its interface.

use bytes::BytesMut;
use error::Result;
use std;
use std::fs::{create_dir, remove_file};
use std::iter::Iterator;
use std::path::{Path, PathBuf};
use std::io;
use std::str;
use std::net::{SocketAddr, IpAddr};
use types::{PeerInfo, InterfaceInfo};
use hex::{FromHex};

use futures::{Future, Stream};
use futures::unsync::mpsc;
use tokio_io::{AsyncRead, AsyncWrite};
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
    UpdatePeer(PeerInfo),
    RemovePeer([u8; 32]),
    RemoveAllPeers,
}

impl UpdateEvent {
    fn from(items: Vec<(String, String)>) -> Vec<UpdateEvent> {
        let mut events = vec![];
        let mut public_key: Option<[u8; 32]> = None;
        let mut preshared_key: Option<[u8; 32]> = None;
        let mut allowed_ips: Vec<(IpAddr, u32)> = vec![];
        let mut keep_alive_interval: Option<u16> = None;
        let mut endpoint: Option<SocketAddr> = None;

        for (key, value) in items {
            match key.as_ref() {
                "private_key" => {
                    let key = <[u8; 32]>::from_hex(&value).unwrap();
                    events.push(UpdateEvent::PrivateKey(key));
                },
                "listen_port" => { events.push(UpdateEvent::ListenPort(value.parse().unwrap())); },
                "public_key" => {
                    if let Some(ref pubkey) = public_key {
                        events.push(UpdateEvent::UpdatePeer(PeerInfo {
                            pub_key: pubkey.clone(),
                            psk: preshared_key.clone(),
                            endpoint: endpoint.clone(),
                            allowed_ips: allowed_ips.clone(),
                            keep_alive_interval: keep_alive_interval.clone(),
                        }));
                    }
                    let key = <[u8; 32]>::from_hex(&value).unwrap();
                    public_key = Some(key);
                },
                "preshared_key" => { preshared_key = Some(<[u8; 32]>::from_hex(&value).unwrap()); },
                "allowed_ip" => {
                    let (ip, cidr) = value.split_at(value.find('/').unwrap());
                    allowed_ips.push((ip.parse().unwrap(), (&cidr[1..]).parse().unwrap()))
                },
                "persistent_keepalive_interval" => {
                    keep_alive_interval = Some(value.parse().unwrap());
                },
                "endpoint" => { endpoint = Some(value.parse().unwrap()); },
                _ => {}
            }
        }

        if let Some(ref pubkey) = public_key {
            events.push(UpdateEvent::UpdatePeer(PeerInfo {
                pub_key: pubkey.clone(),
                psk: preshared_key.clone(),
                endpoint: endpoint.clone(),
                allowed_ips: allowed_ips.clone(),
                keep_alive_interval: keep_alive_interval.clone(),
            }));
        }
        debug!("events {:?}", events);
        events
    }
}

pub struct ConfigurationCodec;

impl Decoder for ConfigurationCodec {
    type Item = Command;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> std::result::Result<Option<Self::Item>, Self::Error> {
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
        let command = if cmd == "get" {
            Command::Get(version.parse().unwrap())
        } else {
            Command::Set(version.parse().unwrap(), UpdateEvent::from(items))
        };

        Ok(Some(command))
    }
}

impl Encoder for ConfigurationCodec {
    type Item = String;
    type Error = io::Error;

    fn encode(&mut self, msg: Self::Item, buf: &mut BytesMut) -> std::result::Result<(), Self::Error> {
        buf.extend(msg.as_bytes());
        buf.extend(b"\n\n");
        Ok(())
    }
}


//pub struct ConfigurationService {
//    interface_name: String,
//    peers: Rc<RefCell<HashMap<[u8; 32], Rc<RefCell<Peer>>>>>,
//    interface_info: Rc<RefCell<InterfaceInfo>>,
//    tx: mpsc::Sender<UpdateEvent>,
//}

//impl Service for ConfigurationService {
//    type Request = Command;
//    type Response = String;
//    type Error = io::Error;
//    type Future = Box<Future<Item=Self::Response, Error=Self::Error>>;
//
//    fn call(&self, req: Self::Request) -> Self::Future {
//        debug!("{:?}", req);
//        match req {
//            Command::Get(version) => {
//                // see: https://www.wireguard.com/xplatform/
//                // this is just bullshit fillin
//                let buf = "private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a
//listen_port=12912
//public_key=b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33
//preshared_key=188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52
//allowed_ip=192.168.4.4/32
//endpoint=[abcd:23::33%2]:51820
//public_key=58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376
//tx_bytes=38333
//rx_bytes=2224
//allowed_ip=192.168.4.6/32
//persistent_keepalive_interval=111
//endpoint=182.122.22.19:3233
//public_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58
//endpoint=5.152.198.39:51820
//allowed_ip=192.168.4.10/32
//allowed_ip=192.168.4.11/32
//tx_bytes=1212111
//rx_bytes=1929999999
//errno=0
//\n";
//                Box::new(future::ok(buf.into()))
//            },
//            Command::Set(version, items) => {
//                let mut public_key = None;
//                let mut preshared_key = None;
//                let mut allowed_ips: Vec<(IpAddr, u32)> = vec![];
//                let mut persistent_keepalive_interval: Option<u16> = None;
//                let mut endpoint: Option<SocketAddr> = None;
//
//                for (key, value) in items {
//                    match key.as_ref() {
////                        "private_key" => { config.key = Some(value); },
////                        "fwmark" => { config.fwmark = Some(value.parse().unwrap()); },
////                        "listen_port" => { config.listen_port = Some(value.parse().unwrap()); },
//                        "public_key" => {
//                            if let Some(ref pubkey) = public_key {
////                                config.peers.push(Peer {
////                                    peer_pubkey: [0u8; 32],
////                                    psk: preshared_key,
////                                    endpoint: endpoint,
////                                    allowed_ips: allowed_ips.clone(),
////                                    keep_alive_interval: persistent_keepalive_interval,
////                                });
//                            }
//                            public_key = Some(value);
//                        },
//                        "preshared_key" => { preshared_key = Some([0u8; 32]); },
//                        "allowed_ip" => {
//                            let (ip, cidr) = value.split_at(value.find('/').unwrap());
//                            debug!("parsed allowed ip as ({}, {})", ip, &cidr[1..]);
//                            allowed_ips.push((ip.parse().unwrap(), (&cidr[1..]).parse().unwrap()))
//                        },
//                        "persistent_keepalive_interval" => {
//                            debug!("persistent_keepalive_interval");
//                            persistent_keepalive_interval = Some(value.parse().unwrap());
//                        },
//                        "endpoint" => { endpoint = Some(value.parse().unwrap()); },
//                        _ => {}
//                    }
//                }
//                Box::new(future::ok("errno=0\nerrno=0\n\n".into()))
//            },
//            _ => {
//                Box::new(future::ok("errno=1\nerrno=1\n\n".into()))
//            }
//        }
//    }
//}

pub struct ConfigurationServiceManager {
    interface_name: String,
}

impl ConfigurationServiceManager {
    pub fn new(interface_name: &str) -> Self {
        ConfigurationServiceManager {
            interface_name: interface_name.into(),
        }
    }

    /// Creates a new `WireGuard` instance
    pub fn get_path(name: &str) -> Result<PathBuf> {
        //        let _tun = Tun::create(Some("hey"));
        // Create the socket directory if not existing
        let mut socket_path = Self::get_run_path().join("wireguard");

        if !socket_path.exists() {
            debug!("Creating socket path: {}", socket_path.display());
            create_dir(&socket_path)?;
        }
        debug!("Setting chmod 0700 of socket path: {}",
               socket_path.display());
        Self::chmod(&socket_path, 0o700)?;

        // Finish the socket path
        socket_path.push(&name);
        socket_path.set_extension("sock");
        if socket_path.exists() {
            debug!("Removing existing socket: {}", socket_path.display());
            remove_file(&socket_path)?;
        }

        Ok(socket_path)
    }

    #[cfg(unix)]
    /// Sets the permissions to a given `Path`
    fn chmod(path: &Path, perms: u32) -> Result<()> {
        use std::os::unix::prelude::PermissionsExt;
        use std::fs::{set_permissions, Permissions};
        set_permissions(path, Permissions::from_mode(perms))?;
        Ok(())
    }

    #[cfg(windows)]
    /// Sets the permissions to a given `Path`
    fn chmod(_path: &Path, _perms: u32) -> Result<()> {
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
            debug!("Removing socket on drop: {}", socket_path.display());
            let _ = remove_file(&socket_path);
        }
    }
}
