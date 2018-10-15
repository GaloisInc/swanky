![fancy garbling logo](logo.png)

# fancy-garbling
Implementation of the BMR16 arithmetic garbling scheme.

# compiling
Requires a recentish version of Rust

* `cargo test` run the tests
* `cargo bench` run the benchmarks

We include an optimization that speeds up base conversion 50x. To enable this, you must
generate base conversion truth tables by invoking `./scripts/create_base_conversion_tables.sh`.
This overwrites the stub C source file `base_conversion/cbits/base_conversion_tables.c`.
Fully generated truth tables are not included in the repo because they are too big.
