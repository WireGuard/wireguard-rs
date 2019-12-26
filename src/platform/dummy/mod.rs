mod endpoint;
mod tun;
mod udp;

/* A pure dummy platform available during "test-time"
 *
 * The use of the dummy platform is to enable unit testing of full WireGuard,
 * the configuration interface and the UAPI parser.
 */

pub use endpoint::*;
pub use tun::*;
pub use udp::*;
