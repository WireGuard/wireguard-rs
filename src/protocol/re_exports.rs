// Copyright 2017 Sopium

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

extern crate noise_protocol;
extern crate noise_sodiumoxide;

pub use self::noise_protocol::{Cipher, DH, Hash, U8Array};
pub use self::noise_sodiumoxide::{ChaCha20Poly1305, Sensitive, X25519};
pub use self::noise_sodiumoxide::init as sodium_init;
