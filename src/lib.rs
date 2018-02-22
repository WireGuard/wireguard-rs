#![feature(ip_constructors)]
#![feature(try_trait)]
#![feature(test)]

#![cfg_attr(feature = "cargo-clippy", allow(doc_markdown))]
#![cfg_attr(feature = "cargo-clippy", allow(unreadable_literal))]
#![cfg_attr(feature = "cargo-clippy", allow(decimal_literal_representation))]

#[macro_use] extern crate failure;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate log;

extern crate base64;
extern crate blake2_rfc;
extern crate byteorder;
extern crate bytes;
extern crate chacha20_poly1305_aead;
extern crate env_logger;
extern crate futures;
extern crate hex;
extern crate nix;
extern crate pnet_packet;
extern crate rand;
extern crate snow;
extern crate socket2;
extern crate subtle;
extern crate test;
extern crate time;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_uds;
extern crate tokio_utun;
extern crate tokio_timer;
extern crate treebitmap;
extern crate x25519_dalek;

pub mod consts;
pub mod cookie;
pub mod error;
pub mod interface;
pub mod noise;
pub mod peer;
pub mod types;
pub mod anti_replay;
pub mod router;
pub mod tai64n;
pub mod timer;
pub mod ip_packet;
pub mod xchacha20poly1305;


