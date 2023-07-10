# Diet Mac'n'Cheese

Diet Mac'n'Cheese is an implementation of the QuickSilver / Mac'n'Cheese
zero-knowledge proof system supporting the SIEVE Circuit IR.

Run `cargo doc --open --no-deps` for available documentation.

## Supported Circuit IR Plugins

The below table presents the existing support levels for the various
standardized SIEVE Circuit IR plugins. `✔` denotes fully supported, `✘` denotes not
supported, and `〜` denotes partially supported.


| Plugin              | Supported? | Notes           |
| ------------------- | ---------- | --------------- |
| extended-arithmetic | `✘`        |                 |
| iter                | `✔`        |                 |
| permutation-check   | `〜`       | Arithmetic only |
| mux                 | `〜`       | Boolean only    |
| ram                 | `✘`        |                 |
| vectors             | `✔`        |                 |

## Running 

We provide an executable program `dietmc_zki` to run the protocol as a verifier or a prover:

```bash
# Verifier
cargo run --release --bin dietmc_zki --features "exe" -- \
  --instance <PATH>/*.ins.sieve \
  --relation <PATH>/*.rel.sieve

# Prover
cargo run --release --bin dietmc_zki --features "exe" -- \
  --instance <PATH>/*.ins.sieve \
  --relation <PATH>/*.rel.sieve \
  prover \
  --witness  <PATH>/*.wit.sieve
```


## SIEVE IR0+

Diet Mac'n'Cheese provides a program `bin/dietmc_0p.rs` to run SIEVE IR0+ circuits.

```bash
cargo run --bin dietmc_0p --features=exe --release -- --instance <PATH>/*.sieve --relation <PATH>/*.sieve

cargo run --bin dietmc_0p --features=exe --release -- --instance <PATH>/*.sieve --relation <PATH>/*.sieve \
  prover --witness <PATH>/*.sieve
```


## Compile flatbuffer sieveir

```bash
cd src/sieveir_phase2/
flatc --rust --gen-onefile sieve_ir.fbs
```
