use clear_on_drop::clear::Clear;
use std::fmt;
use std::time::Instant;

#[cfg(test)]
pub fn dummy_keypair(initiator: bool) -> KeyPair {
    let k1 = Key {
        key: [0x53u8; 32],
        id: 0x646e6573,
    };
    let k2 = Key {
        key: [0x52u8; 32],
        id: 0x76636572,
    };
    if initiator {
        KeyPair {
            birth: Instant::now(),
            initiator: true,
            send: k1,
            recv: k2,
        }
    } else {
        KeyPair {
            birth: Instant::now(),
            initiator: false,
            send: k2,
            recv: k1,
        }
    }
}

#[derive(Clone)]
pub struct Key {
    pub key: [u8; 32],
    pub id: u32,
}

// zero key on drop
impl Drop for Key {
    fn drop(&mut self) {
        self.key.clear()
    }
}

#[cfg(test)]
impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.key[..] == other.key[..]
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key {{ id = {} }}", self.id)
    }
}

#[derive(Clone)]
pub struct KeyPair {
    pub birth: Instant,  // when was the key-pair created
    pub initiator: bool, // has the key-pair been confirmed?
    pub send: Key,       // key for outbound messages
    pub recv: Key,       // key for inbound messages
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyPair {{ initator = {}, age = {} secs, send = {:?}, recv = {:?}}}",
            self.initiator,
            self.birth.elapsed().as_secs(),
            self.send,
            self.recv
        )
    }
}

impl KeyPair {
    pub fn local_id(&self) -> u32 {
        self.recv.id
    }
}
