use hex::FromHex;
use std::net::{IpAddr, SocketAddr};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

use super::{ConfigError, Configuration};

enum ParserState {
    Peer(ParsedPeer),
    Interface,
}

struct ParsedPeer {
    public_key: PublicKey,
    update_only: bool,
    allowed_ips: Vec<(IpAddr, u32)>,
    remove: bool,
    preshared_key: Option<[u8; 32]>,
    replace_allowed_ips: bool,
    persistent_keepalive_interval: Option<u64>,
    protocol_version: Option<usize>,
    endpoint: Option<SocketAddr>,
}

pub struct LineParser<'a, C: Configuration> {
    config: &'a C,
    state: ParserState,
}

impl<'a, C: Configuration> LineParser<'a, C> {
    pub fn new(config: &'a C) -> LineParser<'a, C> {
        LineParser {
            config,
            state: ParserState::Interface,
        }
    }

    fn new_peer(value: &str) -> Result<ParserState, ConfigError> {
        match <[u8; 32]>::from_hex(value) {
            Ok(pk) => Ok(ParserState::Peer(ParsedPeer {
                public_key: PublicKey::from(pk),
                remove: false,
                update_only: false,
                allowed_ips: vec![],
                preshared_key: None,
                replace_allowed_ips: false,
                persistent_keepalive_interval: None,
                protocol_version: None,
                endpoint: None,
            })),
            Err(_) => Err(ConfigError::InvalidHexValue),
        }
    }

    pub fn parse_line(&mut self, key: &str, value: &str) -> Result<(), ConfigError> {
        #[cfg(debug)]
        {
            if key.len() > 0 {
                log::debug!("UAPI: {}={}", key, value);
            }
        }

        // flush peer updates to configuration
        fn flush_peer<C: Configuration>(config: &C, peer: &ParsedPeer) -> Option<ConfigError> {
            if peer.remove {
                log::trace!("flush peer, remove peer");
                config.remove_peer(&peer.public_key);
                return None;
            }

            if !peer.update_only {
                log::trace!("flush peer, add peer");
                config.add_peer(&peer.public_key);
            }

            for (ip, cidr) in &peer.allowed_ips {
                log::trace!("flush peer, add allowed_ips : {}/{}", ip.to_string(), cidr);
                config.add_allowed_ip(&peer.public_key, *ip, *cidr);
            }

            if let Some(psk) = peer.preshared_key {
                log::trace!("flush peer, set preshared_key {}", hex::encode(psk));
                config.set_preshared_key(&peer.public_key, psk);
            }

            if let Some(secs) = peer.persistent_keepalive_interval {
                log::trace!("flush peer, set persistent_keepalive_interval {}", secs);
                config.set_persistent_keepalive_interval(&peer.public_key, secs);
            }

            if let Some(version) = peer.protocol_version {
                log::trace!("flush peer, set protocol_version {}", version);
                if version == 0 || version > config.get_protocol_version() {
                    return Some(ConfigError::UnsupportedProtocolVersion);
                }
            }

            if let Some(endpoint) = peer.endpoint {
                log::trace!("flush peer, set endpoint {}", endpoint.to_string());
                config.set_endpoint(&peer.public_key, endpoint);
            };

            None
        };

        // parse line and update parser state
        match self.state {
            // configure the interface
            ParserState::Interface => match key {
                // opt: set private key
                "private_key" => match <[u8; 32]>::from_hex(value) {
                    Ok(sk) => {
                        self.config.set_private_key(if sk.ct_eq(&[0u8; 32]).into() {
                            None
                        } else {
                            Some(StaticSecret::from(sk))
                        });
                        Ok(())
                    }
                    Err(_) => Err(ConfigError::InvalidHexValue),
                },

                // opt: set listen port
                "listen_port" => match value.parse() {
                    Ok(port) => {
                        self.config.set_listen_port(port)?;
                        Ok(())
                    }
                    Err(_) => Err(ConfigError::InvalidPortNumber),
                },

                // opt: set fwmark
                "fwmark" => match value.parse() {
                    Ok(fwmark) => {
                        self.config
                            .set_fwmark(if fwmark == 0 { None } else { Some(fwmark) })?;
                        Ok(())
                    }
                    Err(_) => Err(ConfigError::InvalidFwmark),
                },

                // opt: remove all peers
                "replace_peers" => match value {
                    "true" => {
                        for p in self.config.get_peers() {
                            self.config.remove_peer(&p.public_key)
                        }
                        Ok(())
                    }
                    _ => Err(ConfigError::UnsupportedValue),
                },

                // opt: transition to peer configuration
                "public_key" => {
                    self.state = Self::new_peer(value)?;
                    Ok(())
                }

                // ignore (end of transcript)
                "" => Ok(()),

                // unknown key
                _ => Err(ConfigError::InvalidKey),
            },

            // configure peers
            ParserState::Peer(ref mut peer) => match key {
                // opt: new peer
                "public_key" => {
                    flush_peer(self.config, &peer);
                    self.state = Self::new_peer(value)?;
                    Ok(())
                }

                // opt: remove peer
                "remove" => {
                    peer.remove = true;
                    Ok(())
                }

                // opt: update only
                "update_only" => {
                    peer.update_only = true;
                    Ok(())
                }

                // opt: set preshared key
                "preshared_key" => match <[u8; 32]>::from_hex(value) {
                    Ok(psk) => {
                        peer.preshared_key = Some(psk);
                        Ok(())
                    }
                    Err(_) => Err(ConfigError::InvalidHexValue),
                },

                // opt: set endpoint
                "endpoint" => match value.parse() {
                    Ok(endpoint) => {
                        peer.endpoint = Some(endpoint);
                        Ok(())
                    }
                    Err(_) => Err(ConfigError::InvalidSocketAddr),
                },

                // opt: set persistent keepalive interval
                "persistent_keepalive_interval" => match value.parse() {
                    Ok(secs) => {
                        peer.persistent_keepalive_interval = Some(secs);
                        Ok(())
                    }
                    Err(_) => Err(ConfigError::InvalidKeepaliveInterval),
                },

                // opt replace allowed ips
                "replace_allowed_ips" => {
                    peer.replace_allowed_ips = true;
                    peer.allowed_ips.clear();
                    Ok(())
                }

                // opt add allowed ips
                "allowed_ip" => {
                    let mut split = value.splitn(2, '/');
                    let addr = split.next().and_then(|x| x.parse().ok());
                    let cidr = split.next().and_then(|x| x.parse().ok());
                    match (addr, cidr) {
                        (Some(addr), Some(cidr)) => {
                            peer.allowed_ips.push((addr, cidr));
                            Ok(())
                        }
                        _ => Err(ConfigError::InvalidAllowedIp),
                    }
                }

                // set protocol version of peer
                "protocol_version" => {
                    let parse_res: Result<usize, _> = value.parse();
                    match parse_res {
                        Ok(version) => {
                            peer.protocol_version = Some(version);
                            Ok(())
                        }
                        Err(_) => Err(ConfigError::UnsupportedProtocolVersion),
                    }
                }

                // flush (used at end of transcipt)
                "" => {
                    log::trace!("UAPI, Set, processes end of transaction");
                    flush_peer(self.config, &peer);
                    Ok(())
                }

                // unknown key
                _ => Err(ConfigError::InvalidKey),
            },
        }
    }
}
