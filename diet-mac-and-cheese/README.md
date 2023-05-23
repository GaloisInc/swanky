# Diet Mac'n'Cheese

Diet Mac'n'Cheese is a library and some programs for zero-knowledge proof of circuit execution.

See documentation for the structures and api the library provides.


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


# SIEVE IR0+

Diet Mac'n'Cheese provides a program `bin/dietmc_0p.rs` to run SIEVE IR0+ circuits.

```bash
cargo run --bin dietmc_0p --features=exe --release -- --instance <PATH>/*.sieve --relation <PATH>/*.sieve

cargo run --bin dietmc_0p --features=exe --release -- --instance <PATH>/*.sieve --relation <PATH>/*.sieve \
  prover --witness <PATH>/*.sieve
```


# Compile flatbuffer sieveir

```bash
cd src/sieveir_phase2/
flatc --rust --gen-onefile sieve_ir.fbs
```