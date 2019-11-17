use super::super::uapi::*;

use std::fs;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};

const SOCK_DIR: &str = "/var/run/wireguard/";

pub struct LinuxUAPI {}

impl PlatformUAPI for LinuxUAPI {
    type Error = io::Error;
    type Bind = UnixListener;

    fn bind(name: &str) -> Result<UnixListener, io::Error> {
        let socket_path = format!("{}{}.sock", SOCK_DIR, name);
        let _ = fs::create_dir_all(SOCK_DIR);
        let _ = fs::remove_file(&socket_path);
        UnixListener::bind(socket_path)
    }
}

impl BindUAPI for UnixListener {
    type Stream = UnixStream;
    type Error = io::Error;

    fn connect(&self) -> Result<UnixStream, io::Error> {
        let (stream, _) = self.accept()?;
        Ok(stream)
    }
}
