use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;
use x25519_dalek::SharedSecret;

/* Mutable part of handshake state */
enum StateMutable {
    Reset,
    InitiationSent,
    InitiationProcessed,
    ReponseSent
}

/* Immutable part of the handshake state */
struct StateFixed {
    sk : StaticSecret,
    pk : PublicKey,
    ss : SharedSecret
}

struct State {
    m : StateMutable,
    f : StateFixed,
}

struct KeyPair {
    send : [u8; 32],
    recv : [u8; 32]
}

impl State {
    /* Initialize a new handshake state machine
     */
    fn new(sk : StaticSecret, pk : PublicKey) -> State {
        let ss = sk.diffie_hellman(&pk);
        State {
            m : StateMutable::Reset,
            f : StateFixed{sk, pk, ss}
        }
    }

    /* Begin a new handshake, returns the initial handshake message
     */
    fn begin(&self) -> Vec<u8> {
        vec![]
    }

    /* Process a handshake message.
     *
     * Result is either a new state (and optionally a new key pair) or an error
     */
    fn process(&self, msg : &[u8]) -> Result<(State, Option<KeyPair>), ()> {
        Err(())
    }
}
