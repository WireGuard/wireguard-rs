use super::timer::Timer;

struct PeerTimers {
    pub send_keepalive: Timer,
    pub new_handshake: Timer,
    pub zero_key_material: Timer,
    pub persistent_keepalive: Timer,
}
