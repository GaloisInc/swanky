# `ocelot`: A rust library for oblivious transfer [![](https://travis-ci.org/amaloz/ocelot.svg?branch=master)](https://travis-ci.org/amaloz/ocelot)

The `ocelot` library implements various one-out-of-two oblivious transfer (+
extension) protocols in rust, alongside oblivious pseudorandom function
protocols inspired by OT. It's the coolest cat in the oblivious transfer world.

`ocelot` implements the following oblivious transfer (OT) protocols:

* Naor-Pinkas semi-honest OT
* Chou-Orlandi malicious OT (including a fix for a security flaw in the existing protocol write-up)
* Asharov-Lindell-Schneider-Zohner semi-honest OT extension (+ correlated and random OT)
* Keller-Orsini-Scholl malicious OT extension (+ correlated and random OT)

And the following oblivious (programmable) PRF protocols:

* Kolesnikov-Kumaresan-Rosulek-Trieu OPRF
* Kolesnikov-Matania-Pinkas-Rosulek-Trieu OPPRF (currently requires the `unstable` feature to use)

It also exposes various traits for implementing your very own OT protocol:

* `Sender` and `Receiver` are the "base" traits for OT. They include an `init`
  function, which does any initial setup and outputs an OT object, and
  `send`/`receive`, which runs the actual OT part. The `send` and `receive`
  functions can be repeated without needing to re-run `init`.

* `CorrelatedSender` / `CorrelatedReceiver` exposes a `send_correlated` /
  `receive_correlated` method for correlated OT.

* `RandomSender` / `RandomReceiver` exposes a `send_random` / `receive_random`
  method for random OT.

**`ocelot` should be considered unstable with potential API changes until
version 1.0 is released**

# Performance

`ocelot` seems to be close in performance with the latest and greatest OT
libraries out there. When running the benchmarks with `1 << 23` OTs we get the
following results (in # million OTs per second and using Chou-Orlandi as the
base OT):

| Protocol |   OT |  COT |  ROT |
|----------|------|------|------|
| ALSZ     | 10.2 | 11.2 | 15.0 |
| KOS      |  8.4 |  9.3 | 11.4 |

For our base OT protocols, we get the following results (in time to run 128
OTs):

| Protocol     | Running Time |
|--------------|--------------|
| Naor-Pinkas  | 21.9 ms      |
| Chou-Orlandi | 17.5 ms      |

All results use unix sockets and were run on a 2.7 GHz machine with 16 GB RAM,
with the sender and receiver run on different threads (see `benches/ot.rs` for
details), using the `nightly` feature (see below).

# Building

Use `cargo build` to build, `cargo test` to run the test suite, `cargo bench` to
benchmark the various protocols, and `cargo doc --open` to view documentation.

`ocelot` also supports the following features:

* `nightly`: Use nightly features from `rust` and the underlying libraries.

* `unstable`: Enable unstable components of `ocelot`.

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
