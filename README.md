# `popsicle`: A rust library for private set intersection

`popsicle` is a rust library that provides protocol implementations for private
set intersection (PSI).

`popsicle` currently implements the following PSI protocols:

* The Pinkas-Schneider-Zohner PSI protocol based on the oblivious PRF of
Kolesnikov-Kumaresan-Rosulek-Trieu.

* The Pinkas-Schnedier-Tkachenko-Yanai PSI protocol based on the oblivious
  programmable PRF of Kolesnikov-Matania-Pinkas-Rosulek-Trieu.

**`popsicle` should be considered unstable and under active development until
version 1.0 is released**

# Building

Use `cargo build` to build, `cargo test` to run the test suite, `cargo bench` to
benchmark the various protocols, and `cargo doc --open` to view documentation.

`popsicle` also supports the following features:

* `nightly`: Use nightly features from `rust` and the underlying libraries.

* `unstable`: Enable unstable components of `popsicle`.

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
