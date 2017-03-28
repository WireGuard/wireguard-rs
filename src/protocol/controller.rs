// Copyright 2017 Guanhao Yin <sopium@mysterious.site>

// This file is part of WireGuard.rs.

// WireGuard.rs is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// WireGuard.rs is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with WireGuard.rs.  If not, see <https://www.gnu.org/licenses/>.

extern crate byteorder;
extern crate noise_protocol;
extern crate noise_sodiumoxide;
extern crate sodiumoxide;
extern crate tai64;
extern crate treebitmap;

use self::byteorder::{ByteOrder, LittleEndian};
use self::noise_protocol::{Cipher, U8Array};
use self::noise_sodiumoxide::ChaCha20Poly1305;
use self::sodiumoxide::randombytes::randombytes_into;
use self::tai64::TAI64N;
use self::treebitmap::{IpLookupTable, IpLookupTableOps};
use protocol::*;
use std::collections::{HashMap, VecDeque};
use std::mem::uninitialized;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::ops::Deref;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::atomic::Ordering::Relaxed;
use std::thread::{Builder, JoinHandle, spawn};
use std::time::{Duration, Instant, SystemTime};
use tun::Tun;

// Some Constants.

// That is, 2 ^ 64 - 2 ^ 16 - 1;
const REKEY_AFTER_MESSAGES: u64 = 0xfffffffffffeffff;
// That is, 2 ^ 64 - 2 ^ 4 - 1;
const REJECT_AFTER_MESSAGES: u64 = 0xffffffffffffffef;

// Timeouts, in seconds.

const REKEY_AFTER_TIME: u64 = 120;
const REJECT_AFTER_TIME: u64 = 180;
const REKEY_TIMEOUT: u64 = 5;
const KEEPALIVE_TIMEOUT: u64 = 10;


const BUFSIZE: usize = 65536;

// How many handshake messages per second is considered normal load.
const HANDSHAKES_PER_SEC: u32 = 250;

// How many packets to queue.
const QUEUE_SIZE: usize = 16;

type SharedPeerState = Arc<RwLock<PeerState>>;

// Locking order:
//
//   info > pubkey_map > any peers > id_map > anything else
//   any peers > rt4 > rt6

/// State of a WG interface.
pub struct WgState {
    info: RwLock<WgInfo>,

    pubkey_map: RwLock<HashMap<X25519Pubkey, SharedPeerState>>,
    id_map: RwLock<HashMap<Id, SharedPeerState>>,
    // Also should be keep in sync. But these should change less often.
    rt4: RwLock<IpLookupTable<Ipv4Addr, SharedPeerState>>,
    rt6: RwLock<IpLookupTable<Ipv6Addr, SharedPeerState>>,

    load_monitor: Mutex<LoadMonitor>,
    // The secret used to calc cookie.
    cookie_secret: Mutex<([u8; 32], Instant)>,
}

/// Removes `Id` from `id_map` when dropped.
struct IdMapGuard {
    wg: Arc<WgState>,
    id: Id,
}

impl Drop for IdMapGuard {
    fn drop(&mut self) {
        if let Ok(mut id_map) = self.wg.id_map.try_write() {
            id_map.remove(&self.id);
        } else {
            let wg = self.wg.clone();
            let id = self.id;
            spawn(move || { wg.id_map.write().unwrap().remove(&id); });
        }
    }
}

impl IdMapGuard {
    fn new(wg: Arc<WgState>, id: Id) -> Self {
        Self { wg: wg, id: id }
    }
}

/// State of a paticular peer.
struct PeerState {
    info: PeerInfo,
    last_handshake: Option<TAI64N>,
    cookie: Option<(Cookie, Instant)>,
    last_mac1: Option<[u8; 16]>,
    handshake: Option<Handshake>,

    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,

    queue: Mutex<VecDeque<Vec<u8>>>,

    // XXX: use a Vec? or ArrayVec?
    transport0: Option<Arc<Transport>>,
    transport1: Option<Arc<Transport>>,
    transport2: Option<Arc<Transport>>,

    // Rekey because of send but not recv in...
    rekey_no_recv: TimerHandle,
    // Keep alive because of recv but not send in...
    keep_alive: TimerHandle,
    // Persistent keep-alive.
    persistent_keep_alive: TimerHandle,
    // Clear all sessions if no new handshake in REJECT_AFTER_TIME * 3.
    clear: TimerHandle,
}

struct Handshake {
    self_id: IdMapGuard,
    hs: HS,
    // Resend after REKEY_TIMEOUT.
    #[allow(dead_code)]
    resend: TimerHandle,
}

type SecretKey = <ChaCha20Poly1305 as Cipher>::Key;

/// A WireGuard transport session.
struct Transport {
    self_id: IdMapGuard,
    peer_id: Id,
    is_initiator: bool,
    // Is set to true after REKEY_AFTER_TIME if `is_initiator`.
    should_handshake: AtomicBool,
    // If we are responder, should not send until received one packet.
    is_initiator_or_has_received: AtomicBool,
    // Also should not send after REJECT_AFTER_TIME,
    // or after REJECT_AFTER_MESSAGES.
    not_too_old: AtomicBool,
    created: Instant,

    send_key: SecretKey,
    send_counter: AtomicU64,

    recv_key: SecretKey,
    recv_ar: Mutex<AntiReplay>,

    // Use mutex to make the compiler happy.
    rekey_after_time: Mutex<TimerHandle>,
    reject_after_time: Mutex<TimerHandle>,
}

fn udp_process_handshake_init(wg: Arc<WgState>, sock: &UdpSocket, p: &[u8], addr: SocketAddr) {
    if p.len() != HANDSHAKE_INIT_LEN {
        return;
    }

    // Lock info.
    let info = wg.info.read().unwrap();
    if !verify_mac1(&info, p) {
        return;
    }

    if wg.check_handshake_load() {
        let cookie = calc_cookie(&wg.get_cookie_secret(), &socket_addr_to_bytes(&addr));
        if !cookie_verify(p, &cookie) {
            debug!("Mac2 verify failed, send cookie reply.");
            let peer_id = Id::from_slice(&p[4..8]);
            let mac1 = get_mac1(p);
            let reply = cookie_reply(info.psk.as_ref(), &info.pubkey, &cookie, peer_id, &mac1);
            sock.send_to(&reply, addr).unwrap();
            return;
        } else {
            debug!("Mac2 verify OK.");
        }
    }

    if let Ok(mut r) = process_initiation(info.deref(), p) {
        let r_pubkey = r.handshake_state.get_rs().unwrap();
        if let Some(peer0) = wg.find_peer_by_pubkey(&r_pubkey) {
            // Lock peer.
            let mut peer = peer0.write().unwrap();

            peer.count_recv(p.len());

            // Compare timestamp.
            if Some(r.timestamp) > peer.last_handshake {
                peer.last_handshake = Some(r.timestamp);
            } else {
                debug!("Handshake timestamp smaller.");
                return;
            }

            let self_id = Id::gen();
            let mut response = responde(info.deref(), &mut r, self_id);

            // Save mac1.
            peer.last_mac1 = Some(get_mac1(&response));

            cookie_sign(&mut response, peer.get_cookie());

            sock.send_to(&response, addr).unwrap();
            peer.count_send((&response).len());

            let t = Transport::new_from_hs(IdMapGuard::new(wg.clone(), self_id),
                                           r.peer_id,
                                           r.handshake_state);
            peer.set_endpoint(addr);
            peer.push_transport(t);
            // Lock id_map.
            wg.id_map.write().unwrap().insert(self_id, peer0.clone());
            debug!("Handshake successful as responder.");
        } else {
            debug!("Get handshake init, but can't find peer by pubkey.");
        }
    } else {
        debug!("Get handshake init, but authentication/decryption failed.");
    }
}

fn udp_process_handshake_resp(wg: &WgState, sock: &UdpSocket, p: &[u8], addr: SocketAddr) {
    if p.len() != HANDSHAKE_RESP_LEN {
        return;
    }

    // Lock info.
    let info = wg.info.read().unwrap();
    if !verify_mac1(&info, p) {
        return;
    }

    if wg.check_handshake_load() {
        let cookie = calc_cookie(&wg.get_cookie_secret(), &socket_addr_to_bytes(&addr));
        if !cookie_verify(p, &cookie) {
            debug!("Mac2 verify failed, send cookie reply.");
            let peer_id = Id::from_slice(&p[4..8]);
            let mac1 = get_mac1(p);
            let reply = cookie_reply(info.psk.as_ref(), &info.pubkey, &cookie, peer_id, &mac1);
            sock.send_to(&reply, addr).unwrap();
            return;
        } else {
            debug!("Mac2 verify OK.");
        }
    }

    let self_id = Id::from_slice(&p[8..12]);

    if let Some(peer0) = wg.find_peer_by_id(self_id) {
        let (peer_id, hs) = {
            // Lock peer.
            let peer = peer0.read().unwrap();
            peer.count_recv(p.len());
            if peer.handshake.is_none() {
                debug!("Get handshake response message, but don't know id.");
                return;
            }
            let handshake = peer.handshake.as_ref().unwrap();
            if handshake.self_id.id != self_id {
                debug!("Get handshake response message, but don't know id.");
                return;
            }

            let mut hs = handshake.hs.clone();
            if let Ok(peer_id) = process_response(&mut hs, p) {
                (peer_id, hs)
            } else {
                debug!("Get handshake response message, auth/decryption failed.");
                return;
            }
            // Release peer.
        };
        debug!("Handshake successful as initiator.");
        // Lock peer.
        let mut peer = peer0.write().unwrap();
        let handle = peer.handshake.take().unwrap().self_id;
        let t = Transport::new_from_hs(handle, peer_id, hs);
        peer.push_transport(t.clone());
        peer.set_endpoint(addr);

        let queued_packets = peer.dequeue_all();
        if queued_packets.is_empty() {
            // Send an empty packet for key confirmation.
            do_keep_alive(&peer, sock);
        } else {
            // Send queued packets.
            let mut buf: [u8; BUFSIZE] = unsafe { uninitialized() };
            for p in queued_packets {
                let encrypted = &mut buf[..p.len() + 32];
                t.encrypt(&p, encrypted).0.unwrap();
                sock.send_to(encrypted, addr).unwrap();
                peer.count_send(encrypted.len());
            }
            peer.on_send(false);
        }

        // Lock id_map.
        wg.id_map.write().unwrap().insert(self_id, peer0.clone());
    } else {
        debug!("Get handshake response message, but don't know id.");
    }
}

/// Maps a `SocketAddr` to bytes.
fn socket_addr_to_bytes(a: &SocketAddr) -> [u8; 16] {
    match a.ip() {
        IpAddr::V4(a) => a.to_ipv6_mapped().octets(),
        IpAddr::V6(a) => a.octets(),
    }
}

fn udp_process_cookie_reply(wg: &WgState, p: &[u8]) {
    let self_id = Id::from_slice(&p[4..8]);

    // Lock info.
    let info = wg.info.read().unwrap();

    if let Some(peer) = wg.find_peer_by_id(self_id) {
        // Lock peer.
        let mut peer = peer.write().unwrap();
        peer.count_recv(p.len());
        if let Some(mac1) = peer.last_mac1 {
            if let Ok(cookie) = process_cookie_reply(info.psk.as_ref(),
                                                     &peer.info.peer_pubkey,
                                                     &mac1,
                                                     p) {
                peer.cookie = Some((cookie, Instant::now()));
            } else {
                debug!("Process cookie reply: auth/decryption failed.");
            }
        }
    }
}

fn udp_process_transport(wg: &WgState, tun: &Tun, p: &[u8], addr: SocketAddr) {
    if p.len() < 32 {
        return;
    }

    let self_id = Id::from_slice(&p[4..8]);

    let maybe_peer0 = wg.find_peer_by_id(self_id);

    if maybe_peer0.is_none() {
        debug!("Get transport message, but don't know id.");
        return;
    }

    let peer0 = maybe_peer0.unwrap();
    let should_set_endpoint = {
        // Lock peer.
        let peer = peer0.read().unwrap();
        peer.count_recv(p.len());
        if let Some(t) = peer.find_transport_by_id(self_id) {
            let mut buff: [u8; BUFSIZE] = unsafe { uninitialized() };
            let decrypted = &mut buff[..p.len() - 32];
            if t.decrypt(p, decrypted).is_ok() {
                if let Ok((len, src, _)) = parse_ip_packet(decrypted) {
                    // Reverse path filtering.
                    let peer1 = wg.find_peer_by_ip(src);
                    if peer1.is_none() || !Arc::ptr_eq(&peer0, &peer1.unwrap()) {
                        debug!("Get transport message: allowed IPs check failed.");
                    } else {
                        if len as usize <= decrypted.len() {
                            tun.write(&decrypted[..len as usize]).unwrap();
                        } else {
                            debug!("Get transport message: packet truncated?");
                        }
                    }
                }
                peer.on_recv(decrypted.len() == 0);
                peer.info.endpoint != Some(addr)
            } else {
                debug!("Get transport message, decryption failed.");
                false
            }
        } else {
            false
        }
        // Release peer.
    };
    if should_set_endpoint {
        // Lock peer.
        peer0.write()
            .unwrap()
            .set_endpoint(addr);
    }
}

/// Start a new thread to recv and process UDP packets.
///
/// This thread runs forever.
pub fn start_udp_processing(wg: Arc<WgState>, sock: Arc<UdpSocket>, tun: Arc<Tun>) -> JoinHandle<()> {
    Builder::new().name("UDP".to_string()).spawn(move || {
        let mut p = [0u8; BUFSIZE];
        loop {
            let (len, addr) = sock.recv_from(&mut p).unwrap();

            if len < 12 {
                continue;
            }

            let type_ = p[0];
            let p = &p[..len];

            match type_ {
                1 => udp_process_handshake_init(wg.clone(), sock.as_ref(), p, addr),
                2 => udp_process_handshake_resp(wg.as_ref(), sock.as_ref(), p, addr),
                3 => udp_process_cookie_reply(wg.as_ref(), p),
                4 => udp_process_transport(wg.as_ref(), tun.as_ref(), p, addr),
                _ => (),
            }
        }
    }).unwrap()
}

// Packets >= MAX_PADDING won't be padded.
// 1280 should be a reasonable conservative choice.
const MAX_PADDING: usize = 1280;

const PADDING_MASK: usize = 0b1111;

fn pad_len(len: usize) -> usize {
    if len >= MAX_PADDING {
        len
    } else {
        // Next multiply of 16.
        (len & !PADDING_MASK) + if len & PADDING_MASK == 0 {
            0
        } else {
            16
        }
    }
}

#[cfg(test)]
#[test]
fn padding() {
    assert_eq!(pad_len(0), 0);
    for i in 1..16 {
        assert_eq!(pad_len(i), 16);
    }

    for i in 17..32 {
        assert_eq!(pad_len(i), 32);
    }

    for i in 1265..1280 {
        assert_eq!(pad_len(i), 1280);
    }
}

/// Start a new thread to read and process packets from TUN device.
///
/// This thread runs forever.
pub fn start_tun_packet_processing(wg: Arc<WgState>, sock: Arc<UdpSocket>, tun: Arc<Tun>) -> JoinHandle<()> {
    Builder::new().name("TUN".to_string()).spawn(move || {
        let mut pkt = [0u8; BUFSIZE];
        loop {
            let len = tun.read(&mut pkt).unwrap();
            let padded_len = pad_len(len);
            // Do not leak other packets' data!
            for b in &mut pkt[len..padded_len] {
                *b = 0;
            }
            let pkt = &pkt[..padded_len];

            let parse_result = parse_ip_packet(pkt);
            if parse_result.is_err() {
                error!("Get packet from TUN device, but failed to parse it!");
                continue;
            }
            let dst = parse_result.unwrap().2;

            let peer = wg.find_peer_by_ip(dst);
            if peer.is_none() {
                // TODO ICMP no route to host.
                debug!("No route to host: {}", dst);
                continue;
            }
            let peer0 = peer.unwrap();
            let should_handshake = {
                // Lock peer.
                let peer = peer0.read().unwrap();
                if peer.get_endpoint().is_none() {
                    // TODO ICMP host unreachable?
                    continue;
                }

                if let Some(t) = peer.find_transport_to_send() {
                    let mut encrypted: [u8; BUFSIZE] = unsafe { uninitialized() };
                    let encrypted = &mut encrypted[..pkt.len() + 32];
                    let (result, should_handshake) = t.encrypt(pkt, encrypted);
                    if result.is_ok() {
                        sock.send_to(encrypted, peer.get_endpoint().unwrap()).unwrap();
                        peer.count_send(encrypted.len());
                        peer.on_send(false);
                    }
                    // Optimization: don't bother `do_handshake` if there is already
                    // an ongoing handshake.
                    should_handshake && peer.handshake.is_none()
                } else {
                    peer.enqueue_packet(pkt);

                    // Optimization: don't bother `do_handshake` if there is already
                    // an ongoing handshake.
                    peer.handshake.is_none()
                }
                // Release peer.
            };

            if should_handshake {
                do_handshake(wg.clone(), peer0, sock.clone());
            }
        }
    }).unwrap()
}

/// Start handshake.
///
/// Better not hold any locks when calling this.
//
/// Nothing happens if there is already an ongoing handshake for this peer.
/// Nothing happens if we don't know peer endpoint.
fn do_handshake(wg: Arc<WgState>, peer0: SharedPeerState, sock: Arc<UdpSocket>) {
    // Lock info.
    let info = wg.info.read().unwrap();

    // Lock peer.
    let mut peer = peer0.write().unwrap();
    if peer.handshake.is_some() {
        return;
    }
    let endpoint = if peer.get_endpoint().is_none() {
        return;
    } else {
        peer.get_endpoint().unwrap()
    };

    debug!("Handshake init.");

    let id = Id::gen();
    // Lock id_map.
    wg.id_map.write().unwrap().insert(id, peer0.clone());
    let handle = IdMapGuard::new(wg.clone(), id);

    let (mut i, hs) = initiate(info.deref(), &peer.info, id);
    cookie_sign(&mut i, peer.get_cookie());

    sock.send_to(&i, endpoint).unwrap();
    peer.count_send((&i).len());

    peer.last_mac1 = Some(get_mac1(&i));

    let resend = {
        let wg = wg.clone();
        let sock = sock.clone();
        let peer = Arc::downgrade(&peer0);
        Box::new(move || {
            debug!("Timer: resend.");
            peer.upgrade().map(|p| {
                p.write().unwrap().handshake = None;
                do_handshake(wg.clone(), p, sock.clone());
            });
        })
    };

    let resend = CONTROLLER.register_delay(Duration::from_secs(REKEY_TIMEOUT), resend);
    resend.activate();

    peer.handshake = Some(Handshake {
        self_id: handle,
        hs: hs,
        resend: resend,
    });

    peer.clear.adjust_and_activate_if_not_activated(3 * REJECT_AFTER_TIME);
}

fn do_keep_alive(peer: &PeerState, sock: &UdpSocket) {
    let e = peer.get_endpoint();
    if e.is_none() {
        return;
    }
    let e = e.unwrap();

    let t = peer.find_transport_to_send();
    if t.is_none() {
        return;
    }
    let t = t.unwrap();

    let mut out = [0u8; 32];
    if t.encrypt(&[], &mut out).0.is_err() {
        return;
    }

    debug!("Keep alive.");
    sock.send_to(&out, e).unwrap();
    peer.count_send(out.len());

    peer.on_send(true);
}

// Cannot be methods because we need `Arc<WgState>`.

/// Query state of the WG interface.
pub fn wg_query_state(wg: Arc<WgState>) -> WgStateOut {
    let peers = {
        // Lock pubkey map.
        let pubkey_map = wg.pubkey_map.read().unwrap();

        pubkey_map.values().map(|p| {
            // Lock peer.
            let peer = p.read().unwrap();

            PeerStateOut {
                public_key: peer.info.peer_pubkey,
                endpoint: peer.info.endpoint,
                last_handshake_time: peer.get_last_handshake_time(),
                rx_bytes: peer.rx_bytes.load(Relaxed),
                tx_bytes: peer.tx_bytes.load(Relaxed),
                persistent_keepalive_interval: peer.info.keep_alive_interval,
                allowed_ips: peer.info.allowed_ips.clone(),
            }
            // Release peer.
        }).collect()
        // Release pubkey map.
    };

    // Lock info.
    let info = wg.info.read().unwrap();
    WgStateOut {
        private_key: info.key.clone(),
        public_key: info.pubkey,
        preshared_key: info.psk,
        peers: peers,
    }
    // Release info.
}

/// Change WG interface configuration.
///
/// All existing sessions and handshakes will be cleared, on the assumption that
/// our crypto keys has changed!
pub fn wg_change_info<F>(wg: Arc<WgState>, f: F)
    where F: FnOnce(&mut WgInfo),
{
    // Lock info.
    let mut info = wg.info.write().unwrap();

    // Lock pubkey map.
    let pubkey_map = wg.pubkey_map.read().unwrap();

    for p in pubkey_map.values() {
        // Lock peer.
        p.write().unwrap().clear();
        // Release peer.
    }

    drop(pubkey_map);
    // Release pubkey_map.

    f(&mut info);
    // Release info.
}

/// Remove a peer.
///
/// Returns: whether there was indeed such a peer, with that public key,
/// that has been removed.
pub fn wg_remove_peer(wg: Arc<WgState>, peer_pubkey: &X25519Pubkey) -> bool {
    // Remove from pubkey_map.
    // Lock pubkey_map.
    let mut pubkey_map = wg.pubkey_map.write().unwrap();
    let p = pubkey_map.remove(peer_pubkey);
    if p.is_none() {
        // Release pubkey_map.
        return false;
    }
    let p = p.unwrap();
    drop(pubkey_map);
    // Release pubkey_map.

    // Lock peer.
    let mut peer = p.write().unwrap();
    // This will remove peer from `id_map` through `IdMapGuard`.
    peer.clear();

    // Remove from rt4 / rt6.

    // Lock rt4.
    let mut rt4 = wg.rt4.write().unwrap();
    // Lock rt6.
    let mut rt6 = wg.rt6.write().unwrap();
    for &(a, m) in &peer.info.allowed_ips {
        match a {
            IpAddr::V4(a) => rt4.remove(a, m),
            IpAddr::V6(a) => rt6.remove(a, m),
        };
    }

    true
}

/// Change configuration of a peer.
///
/// If (and only if) peer public key is changed, ongoing handshake and all
/// transport sessions will be cleared.
///
/// Returns whether there was indeed such a peer, with that public key,
/// that has been changed.
pub fn wg_change_peer<F>(wg: Arc<WgState>, peer_pubkey: &X25519Pubkey, f: F) -> bool
    where F: FnOnce(&mut PeerInfo),
{
    let peer = wg.find_peer_by_pubkey(peer_pubkey);
    if peer.is_none() {
        return false;
    }
    let peer0 = peer.unwrap();

    // Lock peer.
    let mut peer = peer0.write().unwrap();
    let old_pubkey = peer.info.peer_pubkey;
    let old_allowed_ips = peer.info.allowed_ips.clone();

    f(&mut peer.info);

    if old_pubkey != peer.info.peer_pubkey {
        peer.clear();
    }

    if old_allowed_ips != peer.info.allowed_ips {
        // Lock rt4.
        let mut rt4 = wg.rt4.write().unwrap();
        // Lock rt6.
        let mut rt6 = wg.rt6.write().unwrap();

        for (a, m) in old_allowed_ips {
            match a {
                IpAddr::V4(a) => rt4.remove(a, m),
                IpAddr::V6(a) => rt6.remove(a, m),
            };
        }

        for &(a, m) in &peer.info.allowed_ips {
            match a {
                IpAddr::V4(a4) => rt4.insert(a4, m, peer0.clone()),
                IpAddr::V6(a6) => rt6.insert(a6, m, peer0.clone()),
            };
        }
    }

    true
}

/// Add a peer to a WG interface.
/// The peer should not already exist.
pub fn wg_add_peer(wg: Arc<WgState>, peer: &PeerInfo, sock: Arc<UdpSocket>) {
    let register = |a| CONTROLLER.register_delay(Duration::from_secs(0), a);

    // Lock pubkey_map.
    let mut pubkey_map = wg.pubkey_map.write().unwrap();

    let ps = PeerState {
        info: peer.clone(),
        last_handshake: None,
        last_mac1: None,
        cookie: None,
        handshake: None,
        rx_bytes: AtomicU64::new(0),
        tx_bytes: AtomicU64::new(0),
        queue: Mutex::new(VecDeque::with_capacity(QUEUE_SIZE)),
        transport0: None,
        transport1: None,
        transport2: None,
        rekey_no_recv: TimerHandle::dummy(),
        keep_alive: TimerHandle::dummy(),
        persistent_keep_alive: TimerHandle::dummy(),
        clear: TimerHandle::dummy(),
    };
    let ps = Arc::new(RwLock::new(ps));

    // Init timers.
    {
        let weak_ps = Arc::downgrade(&ps);
        // Lock peer.
        let mut psw = ps.write().unwrap();
        // Same with rekey.
        psw.rekey_no_recv = {
            let wg = wg.clone();
            let weak_ps = weak_ps.clone();
            let sock = sock.clone();
            register(Box::new(move || {
                weak_ps.upgrade().map(|p| {
                    debug!("Timer: rekey_no_recv.");
                    do_handshake(wg.clone(), p, sock.clone());
                });
            }))
        };
        psw.keep_alive = {
            let weak_ps = weak_ps.clone();
            let sock = sock.clone();
            register(Box::new(move || {
                weak_ps.upgrade().map(|p| {
                    debug!("Timer: keep_alive.");
                    do_keep_alive(&p.read().unwrap(), &sock);
                });
            }))
        };
        psw.persistent_keep_alive = {
            let weak_ps = weak_ps.clone();
            let sock = sock.clone();
            register(Box::new(move || {
                weak_ps.upgrade().map(|p| {
                    debug!("Timer: persistent_keep_alive.");
                    do_keep_alive(&p.read().unwrap(), &sock);
                });
            }))
        };
        psw.clear = {
            let weak_ps = weak_ps.clone();
            register(Box::new(move || {
                weak_ps.upgrade().map(|p| {
                    debug!("Timer: clear.");
                    p.write().unwrap().clear();
                });
            }))
        };
    }

    let mut rt4 = wg.rt4.write().unwrap();
    let mut rt6 = wg.rt6.write().unwrap();

    for &(a, prefix) in &peer.allowed_ips {
        match a {
            IpAddr::V4(a4) => rt4.insert(a4, prefix, ps.clone()),
            IpAddr::V6(a6) => rt6.insert(a6, prefix, ps.clone()),
        };
    }
    pubkey_map.insert(peer.peer_pubkey, ps);
}

impl WgState {
    /// Create a new `WgState` from `WgInfo`.
    pub fn new(info: WgInfo) -> WgState {
        let mut cookie = [0u8; 32];
        randombytes_into(&mut cookie);

        WgState {
            info: RwLock::new(info),
            pubkey_map: RwLock::new(HashMap::with_capacity(1)),
            id_map: RwLock::new(HashMap::with_capacity(4)),
            rt4: RwLock::new(IpLookupTable::new()),
            rt6: RwLock::new(IpLookupTable::new()),
            load_monitor: Mutex::new(LoadMonitor::new(HANDSHAKES_PER_SEC)),
            cookie_secret: Mutex::new((cookie, Instant::now())),
        }
    }

    /// Create a new `WgState`, and add some peers.
    pub fn new_with_peers(info: WgInfo, peers: &[PeerInfo], sock: Arc<UdpSocket>) -> Arc<WgState> {
        let wg = Arc::new(WgState::new(info));

        for p in peers {
            wg_add_peer(wg.clone(), p, sock.clone())
        }

        wg
    }

    // These methods help a lot in avoiding deadlocks.

    fn find_peer_by_id(&self, id: Id) -> Option<SharedPeerState> {
        self.id_map.read().unwrap().get(&id).cloned()
    }

    fn find_peer_by_pubkey(&self, pk: &X25519Pubkey) -> Option<SharedPeerState> {
        self.pubkey_map.read().unwrap().get(pk).cloned()
    }

    /// Find peer by ip address, consulting the routing tables.
    fn find_peer_by_ip(&self, addr: IpAddr) -> Option<SharedPeerState> {
        match addr {
            IpAddr::V4(ip4) => {
                self.rt4.read().unwrap().longest_match(ip4).map(|x| x.2.clone())
            }
            IpAddr::V6(ip6) => {
                self.rt6.read().unwrap().longest_match(ip6).map(|x| x.2.clone())
            }
        }
    }

    fn check_handshake_load(&self) -> bool {
        self.load_monitor.lock().unwrap().check()
    }

    fn get_cookie_secret(&self) -> [u8; 32] {
        let mut cs = self.cookie_secret.lock().unwrap();
        let now = Instant::now();
        if now.duration_since(cs.1) <= Duration::from_secs(120) {
            cs.0
        } else {
            randombytes_into(&mut cs.0);
            cs.1 = now;
            cs.0
        }
    }
}

impl PeerState {
    fn get_endpoint(&self) -> Option<SocketAddr> {
        self.info.endpoint
    }

    fn set_endpoint(&mut self, a: SocketAddr) {
        self.info.endpoint = Some(a)
    }

    fn get_cookie(&self) -> Option<&Cookie> {
        if self.cookie.is_none() {
            return None;
        }
        if self.cookie.as_ref().unwrap().1.elapsed() >= Duration::from_secs(120) {
            return None;
        }
        Some(&self.cookie.as_ref().unwrap().0)
    }

    fn get_last_handshake_time(&self) -> Option<SystemTime> {
        self.transport0.as_ref().map(|t| {
            let dur = t.created.elapsed();
            SystemTime::now() - dur
        })
    }

    fn clear(&mut self) {
        self.handshake = None;
        self.transport0 = None;
        self.transport1 = None;
        self.transport2 = None;

        self.rekey_no_recv.de_activate();
        self.keep_alive.de_activate();
        self.persistent_keep_alive.de_activate();
        self.clear.de_activate();
    }

    fn on_new_transport(&self) {
        self.clear.adjust_and_activate(3 * REJECT_AFTER_TIME);
        self.info.keep_alive_interval.as_ref().map(|i| {
            self.persistent_keep_alive.adjust_and_activate(*i as u64);
        });
    }

    /// Add `size` bytes to the received bytes counter.
    fn count_recv(&self, size: usize) {
        self.rx_bytes.fetch_add(size as u64, Relaxed);
    }

    /// Add `size` bytes to the sent bytes counter.
    fn count_send(&self, size: usize) {
        self.rx_bytes.fetch_add(size as u64, Relaxed);
    }

    fn on_recv(&self, is_keepalive: bool) {
        self.rekey_no_recv.de_activate();
        if !is_keepalive {
            self.keep_alive.adjust_and_activate_if_not_activated(KEEPALIVE_TIMEOUT);
        }
    }

    fn on_send(&self, is_keepalive: bool) {
        self.keep_alive.de_activate();
        if !is_keepalive {
            self.rekey_no_recv.
                adjust_and_activate_if_not_activated(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
        }
        self.info.keep_alive_interval.as_ref().map(|i| {
            self.persistent_keep_alive.adjust_and_activate(*i as u64);
        });
    }

    fn push_transport(&mut self, t: Arc<Transport>) {
        self.on_new_transport();

        self.transport2 = self.transport1.take();
        self.transport1 = self.transport0.take();
        self.transport0 = Some(t);
    }

    /// Find a transport to send packet.
    fn find_transport_to_send(&self) -> Option<&Transport> {
        // If there exists any transport, we rely on timers to init handshake.

        if let Some(ref t) = self.transport0 {
            if t.get_should_send() {
                return Some(t);
            }
        } else {
            return None;
        }

        if let Some(ref t) = self.transport1 {
            if t.get_should_send() {
                return Some(t);
            }
        } else {
            return None;
        }

        if let Some(ref t) = self.transport2 {
            if t.get_should_send() {
                return Some(t);
            }
        }

        None
    }

    fn find_transport_by_id(&self, id: Id) -> Option<&Transport> {
        if let Some(ref t) = self.transport0 {
            if t.get_self_id() == id {
                return Some(t);
            }
        } else {
            return None;
        }

        if let Some(ref t) = self.transport1 {
            if t.get_self_id() == id {
                return Some(t);
            }
        } else {
            return None;
        }

        if let Some(ref t) = self.transport2 {
            if t.get_self_id() == id {
                return Some(t);
            }
        }
        None
    }

    fn enqueue_packet(&self, p: &[u8]) {
        let mut queue = self.queue.lock().unwrap();
        while queue.len() >= QUEUE_SIZE {
            queue.pop_front();
        }
        queue.push_back(p.to_vec());
    }

    fn dequeue_all(&self) -> VecDeque<Vec<u8>> {
        let mut queue = self.queue.lock().unwrap();
        let mut out = VecDeque::with_capacity(QUEUE_SIZE);
        ::std::mem::swap(&mut out, &mut queue);
        out
    }
}

impl Transport {
    fn new_from_hs(self_id: IdMapGuard, peer_id: Id, hs: HS) -> Arc<Transport> {
        let (x, y) = hs.get_ciphers();
        let (s, r) = if hs.get_is_initiator() {
            (x, y)
        } else {
            (y, x)
        };
        let sk = s.extract().0;
        let rk = r.extract().0;

        let t = Arc::new(Transport {
            self_id: self_id,
            peer_id: peer_id,
            should_handshake: AtomicBool::new(false),
            is_initiator: hs.get_is_initiator(),
            is_initiator_or_has_received: AtomicBool::new(hs.get_is_initiator()),
            not_too_old: AtomicBool::new(true),
            send_key: sk,
            recv_key: rk,
            created: Instant::now(),
            recv_ar: Mutex::new(AntiReplay::new()),
            send_counter: AtomicU64::new(0),
            rekey_after_time: Mutex::new(TimerHandle::dummy()),
            reject_after_time: Mutex::new(TimerHandle::dummy()),
        });

        let w = Arc::downgrade(&t);

        if t.is_initiator {
            let w = w.clone();
            let delay = Duration::from_secs(REKEY_AFTER_TIME);
            let r = CONTROLLER.register_delay(delay, Box::new(move || {
                debug!("Timer: mark should handshake.");
                w.upgrade().map(|t| {
                    t.should_handshake.store(true, Relaxed);
                });
            }));
            r.activate();
            *t.rekey_after_time.lock().unwrap() = r;
        }

        {
            let delay = Duration::from_secs(REJECT_AFTER_TIME);
            let r = CONTROLLER.register_delay(delay, Box::new(move || {
                debug!("Timer: mark too old.");
                w.upgrade().map(|t| {
                    t.not_too_old.store(false, Relaxed);
                });
            }));
            r.activate();
            *t.reject_after_time.lock().unwrap() = r;
        }

        t
    }

    fn get_should_send(&self) -> bool {
        self.is_initiator_or_has_received.load(Relaxed) && self.not_too_old.load(Relaxed)
    }

    fn get_self_id(&self) -> Id {
        self.self_id.id
    }

    /// Expect packet with padding.
    ///
    /// Returns: Whether the operation is successful. Whether we should initiate handshake.
    ///
    /// Length: out.len() = msg.len() + 32.
    fn encrypt(&self, msg: &[u8], out: &mut [u8]) -> (Result<(), ()>, bool) {
        let c = self.send_counter.fetch_add(1, Relaxed);
        let mut should_rekey = self.should_handshake.load(Relaxed);

        // This is REALLY REALLY unlikely...
        if c >= REKEY_AFTER_MESSAGES {
            should_rekey = true;
            // Even more unlikely...
            if c >= REJECT_AFTER_MESSAGES {
                self.not_too_old.store(false, Relaxed);
                return (Err(()), should_rekey);
            }
        }

        out[0..4].copy_from_slice(&[4, 0, 0, 0]);
        out[4..8].copy_from_slice(self.peer_id.as_slice());
        LittleEndian::write_u64(&mut out[8..16], c);

        <ChaCha20Poly1305 as Cipher>::encrypt(&self.send_key, c, &[], msg, &mut out[16..]);

        (Ok(()), should_rekey)
    }

    /// Returns packet maybe with padding.
    ///
    /// Length: out.len() + 32 = msg.len().
    fn decrypt(&self, msg: &[u8], out: &mut [u8]) -> Result<(), ()> {
        if msg.len() < 32 {
            return Err(());
        }

        if !self.not_too_old.load(Relaxed) {
            return Err(());
        }

        if msg[0..4] != [4, 0, 0, 0] {
            return Err(());
        }

        let counter = LittleEndian::read_u64(&msg[8..16]);

        if counter >= REJECT_AFTER_MESSAGES {
            return Err(());
        }

        <ChaCha20Poly1305 as Cipher>::decrypt(&self.recv_key, counter, &[], &msg[16..], out)?;

        if !self.recv_ar.lock().unwrap().check_and_update(counter) {
            return Err(());
        }

        self.is_initiator_or_has_received.store(true, Relaxed);

        Ok(())
    }
}
