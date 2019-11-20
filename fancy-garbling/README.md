![fancy garbling logo](logo.png)

# `fancy-garbling`: Library for garbling boolean (+ arithmetic!) circuits

`fancy-garbling` implements the [BMR16](https://eprint.iacr.org/2016/969)
arithmetic garbling scheme, plus some additional bonus features.

**`fancy-garbling` should be considered extremely unstable and under active
development (and research!)**

# Documentation

The documentation can be found here: <https://galoisinc.github.io/swanky/fancy_garbling/>

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
fancy_garbling = { git = "https://github.com/GaloisInc/swanky/fancy-garbling" }
```

# License

MIT License

# Authors

- Brent Carmer <bcarmer@galois.com>

# Acknowledgments

This material is based upon work supported by the ARO and DARPA under Contract
No. W911NF-15-C-0227 and by DARPA and SSC Pacific under Contract No.
N66001-15-C-4070.

Any opinions, findings and conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of
the ARO, SSC Pacific, and DARPA.

Copyright © 2019 Galois, Inc.
