use hex::FromHex;
use x25519_dalek::{PublicKey, StaticSecret};

use super::{ConfigError, Configuration};

struct StreamPeer {
    public_key: PublicKey,
    update_only: bool,
    added: bool,
}

struct StreamParser<C: Configuration> {
    config: C,
    update_only: bool,
    peer: Option<StreamPeer>,
}

impl<C: Configuration> StreamParser<C> {
    fn parse_interface_line(&mut self, key: &str, value: &str) -> (bool, Option<ConfigError>) {
        let err = match key {
            "private_key" => match <[u8; 32]>::from_hex(value) {
                Ok(sk) => {
                    self.config.set_private_key(if sk == [0u8; 32] {
                        None
                    } else {
                        Some(StaticSecret::from(sk))
                    });
                    None
                }
                Err(_) => Some(ConfigError::InvalidHexValue),
            },
            "listen_port" => match value.parse() {
                Ok(port) => {
                    self.config.set_listen_port(Some(port));
                    None
                }
                Err(_) => Some(ConfigError::InvalidPortNumber),
            },
            "fwmark" => match value.parse() {
                Ok(fwmark) => {
                    self.config
                        .set_fwmark(if fwmark == 0 { None } else { Some(fwmark) });
                    None
                }
                Err(_) => Some(ConfigError::InvalidFwmark),
            },
            "replace_peers" => match value {
                "true" => {
                    for p in self.config.get_peers() {
                        self.config.remove_peer(&p.public_key)
                    }
                    None
                }
                _ => Some(ConfigError::UnsupportedValue),
            },

            // transition to peer configuration
            "public_key" => {
                return (true, None);
            }

            // unknown key
            _ => Some(ConfigError::InvalidKey),
        };
        (false, err)
    }

    fn parse_peer_line(&mut self, key: &str, value: &str) -> Option<ConfigError> {
        // add a p
        let mut flush_peer = || match self.peer.as_mut() {
            None => (),
            Some(peer) => {
                if !peer.added {
                    peer.added = true;
                    if !peer.update_only {
                        self.config.add_peer(&peer.public_key);
                    }
                }
            }
        };

        match key {
            // new peer
            "public_key" => {
                // add previous peer
                flush_peer();

                // create state for new peer
                match <[u8; 32]>::from_hex(value) {
                    Ok(pk) => {
                        self.peer = Some(StreamPeer {
                            public_key: PublicKey::from(pk),
                            update_only: false,
                            added: false,
                        });
                        None
                    }
                    Err(_) => Some(ConfigError::InvalidHexValue),
                }
            }

            "remove" => {
                let peer = self.peer.as_ref().unwrap();
                self.config.remove_peer(&peer.public_key);
                None
            }

            "update_only" => {
                let peer = self.peer.as_mut().unwrap();
                peer.update_only = true;
                None
            }

            "preshared_key" => {
                // add peer (if not exists)
                let peer = self.peer.as_mut().unwrap();
                if !peer.added && !peer.update_only {
                    self.config.add_peer(&peer.public_key);
                    peer.added = true;
                }

                // set preshared key
                match <[u8; 32]>::from_hex(value) {
                    Ok(psk) => {
                        self.config.set_preshared_key(
                            &peer.public_key,
                            if psk == [0u8; 32] { None } else { Some(psk) },
                        );
                        None
                    }
                    Err(_) => Some(ConfigError::InvalidHexValue),
                }
            }

            "endpoint" => None,

            "persistent_keepalive_interval" => None,

            "replace_allowed_ips" => None,

            "allowed_ip" => None,

            // set protocol version of peer
            "protocol_version" => {
                let parse_res: Result<usize, _> = value.parse();
                match parse_res {
                    Ok(version) => {
                        if version == 0 || version > self.config.get_protocol_version() {
                            Some(ConfigError::UnsupportedProtocolVersion)
                        } else {
                            None
                        }
                    }
                    Err(_) => Some(ConfigError::UnsupportedProtocolVersion),
                }
            }
            // unknown key
            _ => Some(ConfigError::InvalidKey),
        }
    }
}
