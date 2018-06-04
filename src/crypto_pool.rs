use consts::{PADDING_MULTIPLE, TRANSPORT_OVERHEAD, TRANSPORT_HEADER_SIZE};
use crossbeam;
use crossbeam_channel::{unbounded, Receiver, Sender};
use futures::sync::mpsc;
use futures::executor;
use futures::Sink;
use futures::future::*;
use tokio_threadpool::ThreadPool;
use num_cpus;
use snow::AsyncTransportState;
use std::thread;
use udp::Endpoint;
use message;
use peer::SessionType;
use ip_packet::IpPacket;
use byteorder::{ByteOrder, LittleEndian};

pub enum Work {
    Decrypt((mpsc::UnboundedSender<DecryptResult>, DecryptWork)),
    Encrypt((mpsc::UnboundedSender<EncryptResult>, EncryptWork)),
}

pub struct EncryptWork {
    pub transport: AsyncTransportState,
    pub nonce: u64,
    pub our_index: u32,
    pub their_index: u32,
    pub endpoint: Endpoint,
    pub in_packet: Vec<u8>,
}

pub struct EncryptResult {
    pub endpoint: Endpoint,
    pub our_index: u32,
    pub out_packet: Vec<u8>,
}

pub struct DecryptWork {
    pub transport: AsyncTransportState,
    pub endpoint: Endpoint,
    pub packet: message::Transport,
    pub session_type: SessionType,
}

pub struct DecryptResult {
    pub endpoint: Endpoint,
    pub orig_packet: message::Transport,
    pub out_packet: Vec<u8>,
    pub session_type: SessionType,
}

pub struct Pool {
    pool: ThreadPool,
}

impl Pool {
    pub fn new() -> Self {
        let pool = ThreadPool::new();
        Self {
            pool
        }
    }

    pub fn send(&self, work: Work) {
        self.pool.spawn(lazy(move || {
            worker(work); 
            ok::<(), ()>(()) 
        }));
    }
}

fn worker(work: Work) {
    match work {
        Work::Decrypt((tx, element)) => {
            let mut raw_packet = vec![0u8; element.packet.len()];
            let nonce = element.packet.nonce();
            let len = element.transport.read_transport_message(nonce, element.packet.payload(), &mut raw_packet).unwrap();
            if len > 0 {
                let len = IpPacket::new(&raw_packet[..len])
                    .ok_or_else(||format_err!("invalid IP packet (len {})", len)).unwrap()
                    .length();
                raw_packet.truncate(len as usize);
            } else {
                raw_packet.truncate(0);
            }

            executor::spawn(tx.send(DecryptResult {
                endpoint: element.endpoint,
                orig_packet: element.packet,
                out_packet: raw_packet,
                session_type: element.session_type,
            })).wait_future().unwrap();
        },
        Work::Encrypt((tx, mut element)) => {
            let padding        = if element.in_packet.len() % PADDING_MULTIPLE != 0 {
                PADDING_MULTIPLE - (element.in_packet.len() % PADDING_MULTIPLE)
            } else { 0 };
            let padded_len     = element.in_packet.len() + padding;
            let mut out_packet = vec![0u8; padded_len + TRANSPORT_OVERHEAD];

            out_packet[0] = 4;
            LittleEndian::write_u32(&mut out_packet[4..], element.their_index);
            LittleEndian::write_u64(&mut out_packet[8..], element.nonce);

            element.in_packet.resize(padded_len, 0);
            let len = element.transport.write_transport_message(element.nonce,
                &element.in_packet,
                &mut out_packet[16..]).unwrap();
            out_packet.truncate(TRANSPORT_HEADER_SIZE + len);

            executor::spawn(tx.send(EncryptResult {
                endpoint: element.endpoint,
                our_index: element.our_index,
                out_packet,
            })).wait_future().unwrap();
        }
    }
}