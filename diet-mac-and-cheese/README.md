# Diet Mac'n'Cheese

Diet Mac'n'Cheese is an implementation of the QuickSilver / Mac'n'Cheese
zero-knowledge proof system supporting the SIEVE Circuit IR.

Run `cargo doc --open --no-deps` for available documentation.

## Supported Circuit IR Plugins

The below table presents the existing support levels for the various
standardized SIEVE Circuit IR plugins. `✔` denotes fully supported, `✘` denotes not
supported, and `〜` denotes partially supported.

| Plugin              | Supported? | Notes           |
| ------------------- | :--------: | --------------- |
| extended-arithmetic |    `✘`     |                 |
| iter                |    `✔`     |                 |
| permutation-check   |    `✔`     |                 |
| mux                 |    `✔`     |                 |
| ram                 |    `✘`     |                 |
| vectors             |    `✔`     |                 |

## Running Diet Mac'n'Cheese

The main program is called `dietmc`.
It is expecting inputs for the relation/instance/witness following the standard SIEVE Circuit IR (a.k.a IR0+).
This standard currently has two binary format: flatbuffers and text.

Note that some parameters are set via a TOML-formatted configuration file. These parameters control the
internal behavior of Diet Mac'n'Cheese, such as the LPN parameter size (for SVOLE) and whether to batch
the assert-zero checks. We currently support the following configurable parameters:

```toml
lpn = 'small' # or 'medium' or 'large'
no_batching = true
threads = 4
```

If no configuration file is provided, Diet Mac'n'Cheese assumes the following defaults:

```toml
lpn = 'medium'
no_batching = false
threads = 1
```

To run diet Mac'n'Cheese with inputs in flatbuffers:

```bash
cargo run --bin dietmc --release -- --config <PATH>/dmc.toml --instance <PATH>/*.sieve --relation <PATH>/*.sieve

cargo run --bin dietmc --release -- --config <PATH>/dmc.toml --instance <PATH>/*.sieve --relation <PATH>/*.sieve \
  --witness <PATH>/*.sieve
```

To run diet Mac'n'Cheese with inputs in text format, add a `--text` flag:

```bash
cargo run --bin dietmc --release -- --config <PATH>/dmc.toml --instance <PATH>/*.sieve --relation <PATH>/*.sieve --text

cargo run --bin dietmc --release -- --config <PATH>/dmc.toml --instance <PATH>/*.sieve --relation <PATH>/*.sieve --text \
  --witness <PATH>/*.sieve
```

## Using parameters

### Lpn parameters

Diet Mac'n'Cheese relies on a SVOLE protocol to generate random commitments that are used during
circuit execution. The wires in the circuit that require svole random commitments are the
private inputs to the circuit and every output of a multiplication gate.

The SVOLE random commitments are drawn in batches using extensions of a certain size.
The `lpn` parameter controls the size of these extensions.
There are currently three possible values for the size of the batches
- 2400
- 160_000
- 10_168_000

This is controlled by the `lpn` parameter. Currently `lpn` can be set to `small` or `medium` and
it is mapped to different values for different fields:
* For the common fields like F2 and F61p, `small` means 160_000 and `medium` means 10_168_000.
* For large fields like Secp256k1/Secp256k1order or F384p/F384q,  `small` means 2400 and `medium` means 160_000.

Memory implications: Every SVOLE functionality associated with a particular field needs a queue
the size of its extensions. The number of bytes per svole value in this queue is the sum
of the number of bytes for the field and the number of bytes for its commitement.
For example, for F2 the memory required is 1+8 bytes, for F61p it is 8+8 bytes,
and for Secp256k1 it is 32+32 bytes, etc.

Every svole extension operation requires a few rounds of communications, between 2 and 4.

### Multithreading

`dietmc` may operate single-threaded (the default) or multithreaded.
The parameter associated is `threads` and takes a number as argument.
When the number of threads indicated is greater or equal to 2, then `dietmc` runs multithreaded.
Currently it is expected to spawn one thread per field used in the circuit, for example a circuit using
4 different fields would spawn 4 threads in addition to the main thread, a total of 5 threads,
in that case the `threads` parameter has to be set to 5 `threads = 5`.
When using multiple fields, do not forget to count the field F2 which is used for field switching.

Each thread requires its own tcp connection, therefore the number of threads implies the number
of tcp connections opened.

It is worth noting that multithreading doubles the number of memory required for svole extensions.

### No-batching

By default, if a `check_zero` gate encounters a wire that is not zero, the verifier would notice only at the end
of the protocol running the entire circuit, and this is because the `check_zero` operation is batching its requests.

For debugging purpose it might be convenient to disable this batching feature so `dietmc` aborts
as soon an expected zero wire that is non-zero is encountered. This is likely to provide some hint
about which part of the circuit is failing. This is done by setting the parameter `no_batching = true`.

Note that it has a significant impact on performance by introducing a round of communication per `check_zero` gate.


## Plaintext evaluation

`dietmc` provides a mode for plaintext evaluation using the flag `--plaintext`:
```bash
cargo run --bin dietmc --release -- --instance <PATH>/*.sieve --relation <PATH>/*.sieve \
  --witness <PATH>/*.sieve --plaintext
```

## Compile flatbuffer sieveir

```bash
cd src/sieveir_phase2/
flatc --rust --gen-onefile sieve_ir.fbs
```
