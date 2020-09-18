use std::io;

use super::Configuration;

pub fn serialize<C: Configuration, W: io::Write>(writer: &mut W, config: &C) -> io::Result<()> {
    let mut write = |key: &'static str, value: String| {
        debug_assert!(value.is_ascii());
        debug_assert!(key.is_ascii());
        log::trace!("UAPI: return : {}={}", key, value);
        writer.write_all(key.as_ref())?;
        writer.write_all(b"=")?;
        writer.write_all(value.as_ref())?;
        writer.write_all(b"\n")
    };

    // serialize interface
    config
        .get_private_key()
        .map(|sk| write("private_key", hex::encode(sk.to_bytes())));

    config
        .get_listen_port()
        .map(|port| write("listen_port", port.to_string()));

    config
        .get_fwmark()
        .map(|fwmark| write("fwmark", fwmark.to_string()));

    // serialize all peers
    let mut peers = config.get_peers();
    while let Some(p) = peers.pop() {
        write("public_key", hex::encode(p.public_key.as_bytes()))?;
        write("preshared_key", hex::encode(p.preshared_key))?;
        write("rx_bytes", p.rx_bytes.to_string())?;
        write("tx_bytes", p.tx_bytes.to_string())?;
        write(
            "persistent_keepalive_interval",
            p.persistent_keepalive_interval.to_string(),
        )?;

        if let Some((secs, nsecs)) = p.last_handshake_time {
            write("last_handshake_time_sec", secs.to_string())?;
            write("last_handshake_time_nsec", nsecs.to_string())?;
        }

        if let Some(endpoint) = p.endpoint {
            write("endpoint", endpoint.to_string())?;
        }

        for (ip, cidr) in p.allowed_ips {
            write("allowed_ip", ip.to_string() + "/" + &cidr.to_string())?;
        }
    }

    Ok(())
}
