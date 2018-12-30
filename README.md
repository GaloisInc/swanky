![fancy garbling logo](logo.png)

# fancy-garbling
An implementation of the [BMR16](https://eprint.iacr.org/2016/969) arithmetic garbling scheme.

Extremely unstable, under active development (and research!).

[Documentation](https://spaceships.github.io/fancy-garbling/fancy_garbling/index.html) is a work in progress.

# compiling
Requires at least `rustc 1.31.0` 

* `cargo test`: run the tests
* `cargo bench`: run the benchmarks

# using in your project
To use fancy-garbling in your project, add the following line to your `[dependencies]` entry in `Cargo.toml`:

```
fancy_garbling = { git = "https://github.com/spaceships/fancy-garbling" }
```
