struct Key {
    key : [u8; 32],
    id  : u32
}

pub struct KeyPair {
    confimed : bool, // has the key-pair been confirmed?
    send     : Key,  // key for outbound messages
    recv     : Key   // key for inbound messages
}
