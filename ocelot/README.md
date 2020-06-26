# `ocelot`: A rust library for oblivious transfer

The `ocelot` library implements various one-out-of-two oblivious transfer (+
extension) protocols in rust, alongside oblivious pseudorandom function
protocols inspired by OT. It's the coolest cat in the oblivious transfer world.

`ocelot` implements the following oblivious transfer (OT) protocols:

* [Naor-Pinkas](https://dl.acm.org/doi/pdf/10.1145/301250.301312) semi-honest OT.
* [Chou-Orlandi](https://eprint.iacr.org/2015/267) malicious OT (including a fix
  for a security flaw in the existing protocol write-up).
* [Asharov-Lindell-Schneider-Zohner](https://eprint.iacr.org/2016/602)
  semi-honest OT extension (+ correlated and random OT).
* [Keller-Orsini-Scholl](https://eprint.iacr.org/2015/546) malicious OT
  extension (+ correlated and random OT).

And the following oblivious (programmable) PRF protocols:

* [Kolesnikov-Kumaresan-Rosulek-Trieu](https://eprint.iacr.org/2016/799) OPRF.
* [Kolesnikov-Matania-Pinkas-Rosulek-Trieu](https://eprint.iacr.org/2017/799)
  OPPRF.

It also exposes various traits for implementing your very own OT or OPRF
protocol.

**`ocelot` should be considered unstable with potential API changes until
version 1.0 is released**

# Documentation

The documentation can be found here: <https://galoisinc.github.io/swanky/ocelot/>

# Performance

`ocelot` seems to be close in performance with the latest and greatest OT
libraries out there. When running the benchmarks with `1 << 23` OTs we get the
following results (in # million OTs per second and using Chou-Orlandi as the
base OT):

| Protocol |   OT |  COT |  ROT |
|----------|------|------|------|
| ALSZ     | 10.3 | 11.8 | 15.5 |
| KOS      |  8.7 | 10.0 | 11.1 |

For our base OT protocols, we get the following results (in time to run 128
OTs):

| Protocol     | Running Time |
|--------------|--------------|
| Naor-Pinkas  | 21.9 ms      |
| Chou-Orlandi | 12.7 ms      |

For the OPRFs, we get the following (in # million OPRFs per second and using
Chou-Orlandi as the base OT) when running the benchmarks with `1 << 18` OPRFs:

| Protocol | OPRF |
|----------|------|
| KKRT     |  1.3 |

All results use unix streams and were run on a 2.7 GHz machine with 16 GB RAM,
with the sender and receiver run on different threads (see `benches/ot.rs` for
details), using the `nightly` feature (see below).

# Building

Use `cargo build` to build, `cargo test` to run the test suite, and `cargo
bench` to benchmark the various protocols.

`ocelot` also supports the following features:

* `nightly`: Use nightly features from `rust` and the underlying libraries.

* `unstable`: Enable unstable components of `ocelot`.

# License

MIT License

# Authors

- Alex J. Malozemoff <amaloz@galois.com>

# Acknowledgments

This material is based upon work supported by the ARO and DARPA under Contract
No. W911NF-15-C-0227 and by DARPA and SSC Pacific under Contract No.
N66001-15-C-4070.

Any opinions, findings and conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of
the ARO, SSC Pacific, and DARPA.

Copyright © 2019 Galois, Inc.
