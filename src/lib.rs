#![feature(ip_constructors)]
#![feature(try_trait)]
#![feature(try_from)]
#![feature(test)]

#![cfg_attr(feature = "cargo-clippy", allow(doc_markdown))]
#![cfg_attr(feature = "cargo-clippy", allow(unreadable_literal))]
#![cfg_attr(feature = "cargo-clippy", allow(decimal_literal_representation))]

#[macro_use] extern crate derive_deref;
#[macro_use] extern crate failure;
#[macro_use] extern crate futures;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate log;
#[macro_use] extern crate tokio_core;

extern crate base64;
extern crate blake2_rfc;
extern crate byteorder;
extern crate bytes;
extern crate chacha20_poly1305_aead;
extern crate hex;
extern crate mio;
extern crate nix;
extern crate notify;
extern crate pnet_packet;
extern crate rand;
extern crate snow;
extern crate socket2;
extern crate subtle;
extern crate test;
extern crate tokio_io;
extern crate tokio_uds;
extern crate tokio_utun;
extern crate tokio_timer;
extern crate tokio_signal;
extern crate treebitmap;
extern crate x25519_dalek;

pub mod interface;

mod udp;
mod message;
mod consts;
mod cookie;
mod error;
mod noise;
mod peer;
mod types;
mod anti_replay;
mod router;
mod time;
mod timer;
mod ip_packet;
mod xchacha20poly1305;
