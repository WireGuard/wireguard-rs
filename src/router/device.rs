use std::net::SocketAddr;
use super::super::types::KeyPair;

pub struct Device {

}

pub struct Peer {

}

pub struct PeerRef {}

impl Device {

    pub fn new() -> Device {
        unimplemented!();
    }

    /// Adds a new peer to the device
    /// 
    /// # Returns
    /// 
    /// An opaque value representing the peer.
    pub fn add(&self) -> PeerRef {
        unimplemented!();
    }

    /// Cryptkey routes and sends a plaintext message (IP packet)
    /// 
    /// # Arguments
    /// 
    /// - pt_msg: IP packet to cryptkey route
    /// 
    /// # Returns
    /// 
    /// A peer reference for the peer if no key-pair is currently valid for the destination.
    /// This indicates that a handshake should be initated (see the handshake module).
    /// If this occurs the packet is copied to an internal buffer
    /// and retransmission can be attempted using send_run_queue
    pub fn send(&self, pt_msg: &mut [u8]) -> Option<PeerRef> {
        unimplemented!();
    }

    /// Sends a message directly to the peer.
    /// The router device takes care of discovering/managing the endpoint.
    /// This is used for handshake initiation/response messages
    /// 
    /// # Arguments
    /// 
    /// - peer: Reference to the destination peer
    /// - msg: Message to transmit
    pub fn send_raw(&self, peer: PeerRef, msg: &mut [u8]) {
        unimplemented!();
    }
    

    /// Flush the queue of buffered messages awaiting transmission
    /// 
    /// # Arguments
    /// 
    /// - peer: Reference for the peer to flush
    pub fn flush_queue(&self, peer: PeerRef) {
        unimplemented!();
    }
    
    /// Attempt to route, encrypt and send all elements buffered in the queue
    /// 
    /// # Arguments
    /// 
    /// # Returns
    /// 
    /// A boolean indicating whether packages where sent.
    /// Note: This is used for implicit confirmation of handshakes.
    pub fn send_run_queue(&self, peer: PeerRef) -> bool {
        unimplemented!();
    }

    /// Receive an encrypted transport message
    /// 
    /// # Arguments
    /// 
    /// - ct_msg: Encrypted transport message
    pub fn recv(&self, ct_msg: &mut [u8]) {
        unimplemented!();
    }

    /// Returns the current endpoint known for the peer
    /// 
    /// # Arguments
    /// 
    /// - peer: The peer to retrieve the endpoint for
    pub fn get_endpoint(&self, peer: PeerRef) -> SocketAddr {
        unimplemented!();
    } 

    pub fn set_endpoint(&self, peer: PeerRef, endpoint: SocketAddr) {
        unimplemented!();
    }

    pub fn new_keypair(&self, peer: PeerRef, keypair: KeyPair) {
        unimplemented!();
    }
}