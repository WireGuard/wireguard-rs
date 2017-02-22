extern crate log;
extern crate wireguard;

use log::LogLevel;
use wireguard::{WireGuard, Device};

use std::thread;
use std::io::Read;
use std::time::Duration;
use std::net::UdpSocket;

#[test]
fn success_hello_server() {
    let addr = "127.0.0.1:8080";

    /// Start a server within a separate thread
    let server = thread::spawn(move || {
        WireGuard::dummy(addr)
            .expect("Could not init wireguard dummy")
            .init_logging(LogLevel::Info)
            .expect("Could not setup logging")
            .run()
            .expect("Could not run wireguard core");
    });

    /// Wait until the server has start up
    thread::sleep(Duration::from_secs(2));

    /// Send data to the server
    let socket = UdpSocket::bind("127.0.0.1:12345").expect("Could not bind to address");
    for _ in 0..4 {
        socket.send_to(b"Hello server!\n", addr).expect("Could not send data");
    }

    /// Wait for the server to terminate
    server.join().expect("Could not join server thread");

    /// Check the results
    let device = Device::dummy("wg").expect("Could not create dummy device");
    let mut s = String::new();
    device.get_fd().read_to_string(&mut s).expect("Could not read to String");
    assert_eq!(s.as_bytes(),
               "Hello server!\nHello server!\nHello server!\n".as_bytes());
}

#[test]
fn success_getter() {
    // Create a dummy server
    let addr = "127.0.0.1:8081";
    let wg = WireGuard::dummy(addr).expect("Could not init wireguard dummy");

    // Test `get_addr`
    let a = wg.get_addr().expect("Could not get wireguard server address");
    let b = addr.parse().expect("Could not parse address to socket");
    assert_eq!(a, b);

    // Test `get_device`
    let dummy = Device::dummy("wg").expect("Could not create dummy device");
    let device = wg.get_device();
    assert_eq!(device.get_name(), dummy.get_name());
    assert!(device.is_dummy());
    assert!(dummy.is_dummy());
}
