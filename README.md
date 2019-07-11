# Rabbittun

**Rabbittun** is a fork of the Cloudflare BoringTun project.

Currently the goal is to:

1. Migrate away from the "bring your own crypto primitives" approach of BoringTun
and towards using the crate system. In particular the `***_dalek` libraries and crates for blake2.
The goal being that the Rust community will have a single good implementation of every primitive
and that this project will benefit from additional platform support / speed improvements from upstream crates (in progress).
2. Improve parsing and readability in the handshake code (in progress).
The work progresses in the crate [here](https://github.com/rot256/wg-handshake),
and will eventually get integrated back into this project (in place of `src/noise.rs`).
3. (Ideally) migrate to `tokio` and reduce the amount of `unsafe` code.

The current goal is to get a nice working Linux implementation
(with the platform-specific code separated).

# Usage

Please do not use this project, it is in an even more shaky state than the original BoringTun project.

# Contribution

Any contribution (pull-request or patch) is welcome, including:

1. Code contributions towards one of the stated goals.
2. Additional ideas for making the project less "C++ like" and more maintainable.
3. Ideas for restructuring / compartmentalizing the different components of the implementation.
