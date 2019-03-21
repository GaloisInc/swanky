# `popsicle`: A rust library for private set intersection

`popsicle` is a library written in rust that provides traits and protocol
implementations for private set intersection (PSI).

`popsicle** currently only implements the Pinkas-Schneider-Zohner PSI protocol
based on the oblivious PRF of Kolesnikov-Kumaresan-Rosulek-Trieu. Hopefully more
flavors of PSI will be added in the future.

**`popsicle` should be considered unstable and under active development until
version 1.0 is released**

# Building

Use `cargo build` to build, `cargo test` to run the test suite, `cargo bench` to
benchmark the various protocols, and `cargo doc --open` to view documentation.

`popsicle` also supports the following features:

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
