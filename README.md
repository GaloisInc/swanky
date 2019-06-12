# `twopac`: A rust library for garbled-circuit-based secure two-party computation

The `twopac` library implements various garbled-circuit-based secure two-party
computation (2PC) protocols:

* The standard semi-honest 2PC protocol.
* The publicly verifiable covert 2PC protocol of Hong-Katz-Kolesnikov-Lu-Wang (coming soon!).

**`twopac` should be considered unstable and under active development until
version 1.0 is released**

# Building

Use `cargo build` to build, `cargo test` to run the test suite, and `cargo
bench` to benchmark the various protocols.

`twopac` also supports the following features:

* `nightly`: Use nightly features from `rust` and the underlying libraries.

* `unstable`: Enable unstable components of `twopac`.

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
