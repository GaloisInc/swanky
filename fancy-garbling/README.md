# `fancy-garbling`: streamed garbling of boolean and arithmetic circuits

`fancy-garbling` implements the [BMR16](https://eprint.iacr.org/2016/969)
arithmetic garbling scheme, plus some additional features.

Garbled circuits are a way for two mutually distrusting parties to compute a
function on their inputs, *without revealing their inputs to each other*.  The basic idea
is as follows: first express the function to compute as a circuit.  Then, one party
"garbles" the circuit, producing encrypted truth tables for each gate in the circuit.
These are then given to the other party who evaluates the circuit using encrypted wires.
Each encrypted wire (called a wirelabel) contains a secret value and can be used to open
exactly one ciphertext in the garbled gates given by the evaluator. This new ciphertext is
the output wire, which can be used recursively to evaluate the whole circuit.

In order to fully evaluate a circuit, the parties need a way for the evaluator to receive
the correct input wires for its input without telling the garbler what those values are.
That is what oblivious transfer (OT) is for, and we implement many versions of oblivious
transfer in our [ocelot](https://github.com/GaloisInc/swanky/tree/master/ocelot) library.
A simple protocol which includes both OT and garbled circuits can be considered semi-honest
secure. We implement this in the
[twopac](https://github.com/GaloisInc/swanky/tree/master/fancy-garbling/src/twopac) module
of this crate.

Traditionally, garbled circuits operate over *boolean* circuits, where the values on
wires are either 0 or 1. This means the function you want to evaluate must be written in
terms of boolean logic - ANDs, NOTs, XORs, etc. The costs of the garbled circuit are then
in terms of how expensive each gate is to garble. For Boolean garbled circuits, the state
of the art is 2 ciphertexts (128 bits each) per AND gate and XOR gates are free.  BMR16
innovated by devising a clever protocol which supports modular arithmetic on the wires,
allowing *free addition* for even quite large moduli, while multiplication gates retain
the same cost as traditional boolean garbled circuits for mod 2, are more expensive.

This library in particular supports *streaming*, and most of the complexity of the API
stems from this choice.  Streaming means that garbled gates are encrypted (and sent over
the wire) immediately as they are produced by the garbler.  They do not need to be
retained in memory. This allows us to evaluate extremely large circuits that would not fit
in any modern computer, such as the ones that we create in our [neural network
experiments](https://github.com/GaloisInc/garbled-neural-network-experiments).
Essentially, to use our library you must be able to construct your function in terms of
our `Fancy` DSL. Then, your function will be garbled and evaluated immediately as the DSL
is evaluated. Wires will be conveniently dropped as they go out of scope of your DSL's
functions. A full circuit representation is not necessary to construct, analyze, or hold
in memory. See the [API docs](https://galoisinc.github.io/swanky/fancy_garbling) for
details.

**`fancy-garbling` should be considered unstable and under active development
(and research!)**

# API Documentation

[The documentation can be found here](https://galoisinc.github.io/swanky/fancy_garbling)

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

This research is based upon work supported in part by the Office of the Director of
National Intelligence (ODNI), Intelligence Advanced Research Projects Activity (IARPA) via
Contract No. 2019-1902070006. The views and conclusions contained herein are those of the
authors and should not be interpreted as necessarily representing the official policies,
either express or implied, of ODNI, IARPA, or the U.S. Government. The U.S. Government is
authorized to reproduce and distribute reprints for governmental purposes notwithstanding
any copyright annotation therein.

This material is also based upon work supported by the ARO and DARPA under Contract No.
W911NF-15-C-0227 and by DARPA and SSC Pacific under Contract No. N66001-15-C-4070.

Any opinions, findings and conclusions or recommendations expressed in this material are
those of the author(s) and do not necessarily reflect the views of the ARO, SSC Pacific,
and DARPA.

Copyright © 2019-2020 Galois, Inc.
