![fancy garbling logo](logo.png)

# fancy-garbling
Implementation of the [BMR16](https://eprint.iacr.org/2016/969) arithmetic garbling scheme.

Extremely unstable, under active development (and research!).

[Documentation is here](https://spaceships.github.io/fancy-garbling/fancy_garbling/index.html).
Currently, the best usage examples are the tests in [garble.rs](src/garble.rs).

# compiling
Requires at least `rustc 1.31.0` 

* `cargo test`: run the tests
* `cargo bench`: run the benchmarks

# using it in your project
To use fancy-garbling in your project, add the following line to the `[dependencies]` entry in `Cargo.toml`:

```
fancy_garbling = { git = "https://github.com/spaceships/fancy-garbling" }
```

# license

MIT License

Copyright 2018 Brent Carmer

This material is based in part upon work supported by the ARO and DARPA under Contract No.
W911NF-15-C-0227.

Any opinions, findings and conclusions or recommendations expressed in this material are
those of the author(s) and do not necessarily reflect the views of the ARO and DARPA.
