extern crate log;
extern crate wireguard;

use log::LogLevel;
use wireguard::{WireGuard, Device};

use std::thread;
use std::io::Read;
use std::time::Duration;
use std::net::UdpSocket;

const TEST_ADDR: &'static str = "127.0.0.1:8080";

#[test]
fn success_hello_server() {
    /// Start a server within a separate thread
    let server =
        thread::spawn(move || { WireGuard::dummy().unwrap().init_logging(LogLevel::Info).unwrap().run().unwrap(); });

    /// Wait until the server has start up
    thread::sleep(Duration::from_secs(2));

    /// Send data to the server
    let socket = UdpSocket::bind("127.0.0.1:12345").expect("Could not bind to address");
    for _ in 0..4 {
        socket.send_to(b"Hello server!\n", TEST_ADDR).expect("Could not send data");
    }

    /// Wait for the server to terminate
    server.join().unwrap();

    /// Check the results
    let device = Device::dummy().expect("Could not get dummy device");
    let mut s = String::new();
    device.get_fd().read_to_string(&mut s).expect("Could not read to String");
    assert_eq!(s.as_bytes(),
               "Hello server!\nHello server!\nHello server!\n".as_bytes());
}
