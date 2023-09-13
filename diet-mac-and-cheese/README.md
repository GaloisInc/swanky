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
| permutation-check   |    `〜`    | Arithmetic only |
| mux                 |    `〜`    | Boolean only    |
| ram                 |    `✘`     |                 |
| vectors             |    `✔`     |                 |

## Running Diet Mac'n'Cheese

The main program is called `dietmc_0p`.
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
lpn = 'Medium'
no_batching = false
threads = 1
```

To run diet Mac'n'Cheese with inputs in flatbuffers:

```bash
cargo run --bin dietmc_0p --release -- --config <PATH>/dmc.toml --instance <PATH>/*.sieve --relation <PATH>/*.sieve

cargo run --bin dietmc_0p --release -- --config <PATH>/dmc.toml --instance <PATH>/*.sieve --relation <PATH>/*.sieve \
  --witness <PATH>/*.sieve
```

To run diet Mac'n'Cheese with inputs in text format, add a `--text` flag:

```bash
cargo run --bin dietmc_0p --release -- --config <PATH>/dmc.toml --instance <PATH>/*.sieve --relation <PATH>/*.sieve --text

cargo run --bin dietmc_0p --release -- --config <PATH>/dmc.toml --instance <PATH>/*.sieve --relation <PATH>/*.sieve --text \
  --witness <PATH>/*.sieve
```

## Compile flatbuffer sieveir

```bash
cd src/sieveir_phase2/
flatc --rust --gen-onefile sieve_ir.fbs
```
