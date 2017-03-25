This is a walk-through of the protocol implementation. Hope it will be
helpful if you want to review/hack on it.

## `anti_replay.rs`

Anti replay algorithm from RFC 6479. It is mostly a straightforward
translation from the C code there, with only one notable difference:
the handling of seq number zero.

It is reasonably well tested.

## `cookie.rs`

Cookie signing, verification, cookie reply message generation and
parsing.

It is reasonably well tested.

## `timer.rs`

Timer facility. Uses the hashed timing wheel algorithm. It is
optimized for WireGuard use cases (frequent operations on a mostly
fixed set of timers) with the "activated" atomic boolean flag.

It is under tested.

## `ip.rs`

Parsing of IP(v6) packets.

## `types.rs`

Some common types and constants.

## `handshake.rs`

Handshake initiation and response message generation and parsing.

It is reasonably well tested.

## `controller.rs`

This beast is the most complex... It manages all the states, timers
and does the actuall IO. It also has a lot of locks and `Arc`s.

`WgState` represents the state of a WireGuard interface. It contains a
hash table that maps pubkeys to peers, another hash table that maps
session IDs to peers, and routing tables that map allowed IP(v6)
addresses to peers.

The ID table changes often and needs to be carefully kept in sync with
actuall peer states. (Or we will leak memory.) For this we use
`IdMapGuard` which when dropped will automatically remove an ID from
the map.

`PeerState` represents the state of a peer. It is shared across the
maps and timers with `Arc<RwLock<_>>` (or `Weak<RwLock<>>` for
timers).

The actually IO happens in two threads, one for processing UDP
datagrams, another for processing packets from the TUN device. (It is
possible to use more threads, but there does not seem to be much
benefit without also using SO_REUSEPORT or multi queue tun device.)

The UDP thread repeatedly `recv_from` the socket, and take action
based the type of the message.

The TUN thread repeatedly `read` packets from the TUN device, find the
corresponding peer by looking up the route tables, encrypt them and
send them out if a valid session exists, and/or initiate handshake if
necessary.

### Lock Order

Because we use a lot of locks, care must be taken to avoid deadlock.
We adhere to the following partial order:

    info > pubkey_map > any peers > id_map > anything else
                        any peers > rt4 > rt6

Locks whose order are not defined should not be held at the same time.

### Timer Management

Each peer is associated with the following timers:

#### `rekey_no_recv`

Initiate handshake because we have send a transport message but
haven't received any in 15s (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT).

It is activated and set to 15s when we send a (non-keep-alive)
transport message, unless it is already activated.

It is de-activated when we receive a transport message.

#### `keep_alive`

Send a keep-alive message because we have received a transport message
but haven't sent any in 10s (KEEPALIVE_TIMEOUT).

It is activated and set to 10s when we receive a (non-keep-alive)
transport message, unless it is already activated.

It is de-activated when we send a transport message.

#### `persistent_keep_alive`

Persistent keep-alive.

It is activated and set to the configured interval when a new session
is established, or when we send a transport message.

#### `clear`

Clear handshake and all transport sessions, and de-activate all
timers, because no new session has been established in 9min (3 *
REJECT_AFTER_TIME).

It is activated and set to 9 min when we initiate a handshake, unless
it is already activated.

It is activated and set to 9 min when a new session is established.

### Testing

This module is under tested.

## Copyright and License of this file

Copyright 2017 Guanhao Yin <sopium@mysterious.site>

This file is part of WireGuard.rs

WireGuard.rs is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at
your option) any later version.

WireGuard.rs is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with WireGuard.rs.  If not, see <https://www.gnu.org/licenses/>.
