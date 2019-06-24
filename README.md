![fancy garbling logo](logo.png)

# `fancy-garbling`: Library for garbling boolean (+ arithmetic!) circuits
[![](https://travis-ci.org/GaloisInc/fancy-garbling.svg?branch=master)](https://travis-ci.org/GaloisInc/fancy-garbling)

`fancy-garbling` implements the [BMR16](https://eprint.iacr.org/2016/969)
arithmetic garbling scheme, plus some additional bonus features.

**`fancy-garbling` should be considered extremely unstable and under active
development (and research!)**

# Documentation

[Documentation is here](https://galoisinc.github.io/fancy-garbling/fancy_garbling/).
Currently, the best usage examples are the tests in [garble.rs](src/garble.rs).

# Building

`fancy-garbling` requires at least `rustc 1.31.0`.

* `cargo build`: Build `fancy-garbling`
* `cargo test`: Run the tests
* `cargo bench`: Run the benchmarks

`fancy-garbling` also supports the following features:

* `nightly`: Use nightly features from `rust` and the underlying libraries.

# Using `fancy-garbling` in your project

To use `fancy-garbling` in your project, add the following line to the
`[dependencies]` entry in `Cargo.toml`:

```
fancy_garbling = { git = "https://github.com/spaceships/fancy-garbling" }
```

# License

MIT License

# Authors

- Brent Carmer <bcarmer@galois.com>

# Acknowledgments

This material is based in part upon work supported by the ARO and DARPA under Contract No.
W911NF-15-C-0227.

Any opinions, findings and conclusions or recommendations expressed in this material are
those of the author(s) and do not necessarily reflect the views of the ARO and DARPA.

Copyright © 2019 Galois, Inc.
