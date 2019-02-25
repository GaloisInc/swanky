# The ocelot oblivious transfer library

The `ocelot` library implements various one-out-of-two oblivious transfer (+
extension) protocols in rust. It's the coolest cat in the oblivious transfer
world.

`ocelot` implements the following oblivious transfer (OT) protocols:

* Naor-Pinkas semi-honest OT
* Chou-Orlandi malicious OT
* Asharov-Lindell-Schneider-Zohner semi-honest OT extension (+ correlated and random OT)
* Keller-Orsini-Scholl malicious OT extension

It also exposes various traits for implementing your very own OT protocol:

* `ObliviousTransferSender` and `ObliviousTransferReceiver` are the "base"
  traits for an OT implementation. They include an `init` function, which does
  any initial setup and outputs an OT object, and `send`/`receive`, which runs
  the actual OT part. The `send` and `receive` functions can be repeated without
  needing to re-run `init`.

* `CorrelatedObliviousTransferSender` / `CorrelatedObliviousTransferReceiver`
  exposes a `send_correlated` / `receive_correlated` method for
  correlated OT.

* `RandomObliviousTransferSender` / `RandomObliviousTransferReceiver` exposes a
  `send_random` / `receive_random` method for random OT.

**`ocelot` should be considered unstable and under active development until
version 1.0 is released**

# Performance

`ocelot` seems to be close in performance with the latest and greatest OT
libraries out there. When using the benchmarks with `1 << 23` OTs we get the
following results (in # million OTs per second and using Chou-Orlandi as the
base OT):

| Protocol |  OT |  COT |  ROT |
|----------|-----|------|------|
| ALSZ     | 8.6 | 10.0 | 12.3 |
| KOS      | 7.5 |      |      |

For our base OT protocols, we get the following results (in time to run 128
OTs):

| Protocol     | Running Time |
|--------------|--------------|
| Naor-Pinkas  | 21.9 ms      |
| Chou-Orlandi | 18.5 ms      |

All results use unix sockets and were run on a 2.7 GHz machine with 16 GB RAM,
with the sender and receiver being on different threads (see `benches/ot.rs` for
details).

# Building

Use `cargo build` to build, `cargo test` to run the test suite, `cargo bench` to
benchmark the various protocols, and `cargo doc --open` to view documentation.

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
