use hex::FromHex;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

use super::{ConfigError, Configuration};

struct Serializer<C: Configuration> {
    config: C,
}

impl<C: Configuration> Serializer<C> {
    fn get(&self) -> Vec<String> {
        let mut peers = self.config.get_peers();
        let mut lines = Vec::with_capacity(peers.len() * 6 + 5);
        let mut write = |key, value: String| {
            lines.push(String::new() + key + "=" + &value);
        };

        // serialize interface
        self.config
            .get_private_key()
            .map(|sk| write("private_key", hex::encode(sk.to_bytes())));

        self.config
            .get_listen_port()
            .map(|port| write("listen_port", port.to_string()));

        self.config
            .get_fwmark()
            .map(|fwmark| write("fwmark", fwmark.to_string()));

        // serialize all peers
        while let Some(p) = peers.pop() {
            write("rx_bytes", p.rx_bytes.to_string());
            write("tx_bytes", p.tx_bytes.to_string());
            write(
                "last_handshake_time_sec",
                p.last_handshake_time_nsec.to_string(),
            );
            write(
                "last_handshake_time_nsec",
                p.last_handshake_time_nsec.to_string(),
            );
            write("public_key", hex::encode(p.public_key.as_bytes()));
            p.preshared_key
                .map(|psk| write("preshared_key", hex::encode(psk)));
            for (ip, cidr) in p.allowed_ips {
                write("allowed_ip", ip.to_string() + "/" + &cidr.to_string())
            }
        }

        lines
    }
}
