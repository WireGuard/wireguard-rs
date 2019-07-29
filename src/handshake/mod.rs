/* Implementation of the:
 *
 * Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
 *
 * Protocol pattern, see: http://www.noiseprotocol.org/noise.html.
 * For documentation.
 */

mod device;
mod macs;
mod messages;
mod noise;
mod peer;
mod timestamp;
mod types;

// publicly exposed interface

pub use device::Device;
