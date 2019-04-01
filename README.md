# The `scuttlebutt` multi-party computation utilities toolkit
Or: "Where rust MPC libraries come to drink"

The `scuttlebutt` library provides a bunch of core primitives for building
multi-party computation (MPC) related protocols, such as garbled circuits or
oblivious transfer. In particular, `scuttlebutt` provides the following:

* `AesHash`, which provides a correlation-robust hash function based on fixed-key AES (cf. <https://eprint.iacr.org/2019/074>).
* `AesRng`, which provides a random number generator based on fixed-key AES.
* `Block`, which wraps an `__m128i` type and provides methods useful when used as a garbled circuit wire label.
* A `cointoss` module, which implements a simple random-oracle-based coin-tossing protocol.
* A `utils` module, which contains useful utility functions.

**`scuttlebutt` should be considered unstable and under active development until
version 1.0 is released**

# Building

Use `cargo build` to build, `cargo test` to run the test suite, `cargo bench` to
benchmark the various protocols, and `cargo doc --open` to view documentation.

`scuttlebutt` also supports the following features:

* `nightly`: Use nightly features from `rust` and the underlying libraries.

# License

MIT License

# Authors

- Alex J. Malozemoff <amaloz@galois.com>

# Acknowledgments

This material is based upon work supported by the ARO and DARPA under Contract
No. W911NF-15-C-0227.

Any opinions, findings and conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of
the ARO and DARPA.

Copyright © 2019 Galois, Inc.
