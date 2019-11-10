use hex::FromHex;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

use super::{ConfigError, Configuration};

#[derive(Copy, Clone)]
enum ParserState {
    Peer {
        public_key: PublicKey, // peer identity
        update_only: bool,     // is the update_only flag set
    },
    Interface,
}

struct LineParser<C: Configuration> {
    config: C,
    state: ParserState,
}

struct Serializer<C: Configuration> {
    config: C,
}

impl<C: Configuration> LineParser<C> {
    fn new_peer(value: &str) -> Result<ParserState, ConfigError> {
        match <[u8; 32]>::from_hex(value) {
            Ok(pk) => Ok(ParserState::Peer {
                public_key: PublicKey::from(pk),
                update_only: false,
            }),
            Err(_) => Err(ConfigError::InvalidHexValue),
        }
    }

    fn parse_line(&mut self, key: &str, value: &str) -> Option<ConfigError> {
        let flush_peer = |st: ParserState| -> ParserState {
            match st {
                ParserState::Peer {
                    public_key,
                    update_only: false,
                } => {
                    self.config.add_peer(&public_key);
                    ParserState::Peer {
                        public_key,
                        update_only: true,
                    }
                }
                _ => st,
            }
        };

        // parse line and update parser state
        let new_state = match self.state {
            // configure the interface
            ParserState::Interface => match key {
                // opt: set private key
                "private_key" => match <[u8; 32]>::from_hex(value) {
                    Ok(sk) => {
                        self.config.set_private_key(if sk == [0u8; 32] {
                            None
                        } else {
                            Some(StaticSecret::from(sk))
                        });
                        Ok(self.state)
                    }
                    Err(_) => Err(ConfigError::InvalidHexValue),
                },

                // opt: set listen port
                "listen_port" => match value.parse() {
                    Ok(port) => {
                        self.config.set_listen_port(Some(port));
                        Ok(self.state)
                    }
                    Err(_) => Err(ConfigError::InvalidPortNumber),
                },

                // opt: set fwmark
                "fwmark" => match value.parse() {
                    Ok(fwmark) => {
                        self.config
                            .set_fwmark(if fwmark == 0 { None } else { Some(fwmark) });
                        Ok(self.state)
                    }
                    Err(_) => Err(ConfigError::InvalidFwmark),
                },

                // opt: remove all peers
                "replace_peers" => match value {
                    "true" => {
                        for p in self.config.get_peers() {
                            self.config.remove_peer(&p.public_key)
                        }
                        Ok(self.state)
                    }
                    _ => Err(ConfigError::UnsupportedValue),
                },

                // opt: transition to peer configuration
                "public_key" => Self::new_peer(value),

                // unknown key
                _ => Err(ConfigError::InvalidKey),
            },

            // configure peers
            ParserState::Peer { public_key, .. } => match key {
                // opt: new peer
                "public_key" => {
                    flush_peer(self.state);
                    Self::new_peer(value)
                }

                // opt: remove peer
                "remove" => {
                    self.config.remove_peer(&public_key);
                    Ok(self.state)
                }

                // opt: update only
                "update_only" => Ok(ParserState::Peer {
                    public_key,
                    update_only: true,
                }),

                // opt: set preshared key
                "preshared_key" => match <[u8; 32]>::from_hex(value) {
                    Ok(psk) => {
                        let st = flush_peer(self.state);
                        self.config.set_preshared_key(
                            &public_key,
                            if psk.ct_eq(&[0u8; 32]).into() {
                                None
                            } else {
                                Some(psk)
                            },
                        );
                        Ok(st)
                    }
                    Err(_) => Err(ConfigError::InvalidHexValue),
                },

                // opt: set endpoint
                "endpoint" => match value.parse() {
                    Ok(endpoint) => {
                        let st = flush_peer(self.state);
                        self.config.set_endpoint(&public_key, endpoint);
                        Ok(st)
                    }
                    Err(_) => Err(ConfigError::InvalidSocketAddr),
                },

                // opt: set persistent keepalive interval
                "persistent_keepalive_interval" => match value.parse() {
                    Ok(secs) => {
                        let st = flush_peer(self.state);
                        self.config
                            .set_persistent_keepalive_interval(&public_key, secs);
                        Ok(st)
                    }
                    Err(_) => Err(ConfigError::InvalidKeepaliveInterval),
                },

                // opt replace allowed ips
                "replace_allowed_ips" => {
                    let st = flush_peer(self.state);
                    self.config.replace_allowed_ips(&public_key);
                    Ok(st)
                }

                // opt add allowed ips
                "allowed_ip" => {
                    let mut split = value.splitn(2, "/");
                    let addr = split.next().and_then(|x| x.parse().ok());
                    let cidr = split.next().and_then(|x| x.parse().ok());
                    match (addr, cidr) {
                        (Some(addr), Some(cidr)) => {
                            let st = flush_peer(self.state);
                            self.config.add_allowed_ip(&public_key, addr, cidr);
                            Ok(st)
                        }
                        _ => Err(ConfigError::InvalidAllowedIp),
                    }
                }

                // set protocol version of peer
                "protocol_version" => {
                    let parse_res: Result<usize, _> = value.parse();
                    match parse_res {
                        Ok(version) => {
                            if version == 0 || version > self.config.get_protocol_version() {
                                Err(ConfigError::UnsupportedProtocolVersion)
                            } else {
                                Ok(self.state)
                            }
                        }
                        Err(_) => Err(ConfigError::UnsupportedProtocolVersion),
                    }
                }

                // unknown key
                _ => Err(ConfigError::InvalidKey),
            },
        };

        match new_state {
            Err(e) => Some(e),
            Ok(st) => {
                self.state = st;
                None
            }
        }
    }
}
