# `swanky`: A suite of rust libraries for secure computation

`swanky` provides a suite of rust libraries for doing secure computation.

<!- BEGIN THIS SECTION IS AUTOGENERATED BY ./swanky readme gen-crate-list ->
- **`bristol-fashion`**: A parser for Bristol Fashion circuits.
- **`diet-mac-and-cheese`**: A diet version of the Mac'n'Cheese protocol
- **`fancy-garbling`**: A library for boolean and arithmetic garbling
- **`fancy-garbling-base-conversion`**: Lookup tables useful for the fancy-garbling crate
- **`humidor`**: A test-bed for Ligero-like protocols
- **`inferno`**: An implementation of the Limbo zero knowledge proof protocol
- **`keyed_arena`**: Bump allocator which allows for random access to its allocations
- **`mac-n-cheese-compiler`**: A tool to compile a zero knowledge circuit to the mac n'cheese IR
- **`mac-n-cheese-event-log`**: Utilities to define metrics for mac n'cheese
- **`mac-n-cheese-inspector`**: A tool to inspect mac n'cheese IR files
- **`mac-n-cheese-ir`**: The definition of the mac n'cheese IR
- **`mac-n-cheese-runner`**: A tool to proof mac n'cheese IR files in zero-knowledge
- **`mac-n-cheese-sieve-parser`**: A parser for SIEVE IR (a zero knoweldge proof circuit format)
- **`mac-n-cheese-vole`**: An implementation of Vector Oblivious Linear Evaluation
- **`mac-n-cheese-wire-map`**: An implementation of a sparse array
- **`ocelot`**: A library for oblivious transfer protocols
- **`popsicle`**: A library for private set intersection
- **`scuttlebutt`**: A library of useful multi-party computation utilities
- **`simple-arith-circuit`**: Simple arithmetic circuit library
- **`swanky-field`**: Definitions of the core `FiniteField` and `FiniteRing` traits
- **`swanky-field-binary`**: Binary finite (extension) fields
- **`swanky-field-f61p`**: An implementation of `GF(2^61-1)`
- **`swanky-field-ff-primes`**: Finite field implementations for large prime fields
- **`swanky-field-fft`**: FFT implementations for finite fields
- **`swanky-field-test`**: Utilitites for testing correctness of finite field implementations
- **`swanky-flatbuffer-build`**: Tooling to automate compiling flatbuffer schemas
- **`swanky-party`**: Support for types indexed by a party.
- **`swanky-serialization`**: Traits and utilities for compact serialization into a canonical byte representation
- **`vectoreyes`**: Cross-platform SIMD types and functions
- **`web-mac-n-cheese-wasm`**: Web Mac'n'Cheese, the wasm part
- **`web-mac-n-cheese-websocket`**: Web Mac'n'Cheese, the websocket part
- **`zkv`**: Zero knowledge proofs for verilog files generated using saw / abc
<!- END THIS SECTION IS AUTOGENERATED BY ./swanky readme gen-crate-list ->

# A note on security

`swanky` is currently **research** software. Do not deploy it in production, or trust
it with sensitive data.

Please reach out to us at <swanky@galois.com> if you're interested in using Swanky in a production setting.

# Using `swanky`
## Preferred Way
The preferred way to use `swanky` is to fork this monorepo, and add your code
to your fork. This approach makes it easy for your code to inherit the
configuration of the `swanky` repo.

## Alternative Way
It is also possible to use `swanky` as traditional Rust crates. The downside of
this approach is that you won't automatically get the configuration of the
`swanky` repo. `swanky` is _only_ tested against the pinned rust version in the
repository and the pinned dependency versions.

To use a `swanky` crate in your project, add the following line to the
`[dependencies]` entry in `Cargo.toml`:
```
<crate-name> = { git = "https://github.com/GaloisInc/swanky", rev = "xxxxxx" }
```
where `<crate-name>` is one of the crates listed above and `rev` is the
particular revision to use.

Note: As `swanky` is currently considered prototype software, it is best to pin
a particular revision of `swanky`, as there is no guarantee that future versions
of `swanky` will maintain backwards compatibility.

It is also advisable to copy over swanky's `.cargo/config` file, and to enable
LTO in your release builds (`lto = true` in your `Cargo.toml` file).

# Citing `swanky`

If you use `swanky` in your academic paper, please cite it as follows:
```
@misc{swanky,
    author = {{Galois, Inc.}},
    title = {{swanky}: A suite of rust libraries for secure computation},
    howpublished = {\url{https://github.com/GaloisInc/swanky}},
    year = 2019,
}
```

# License

MIT License

# Contact

You can contact the `swanky` team at `swanky@galois.com`.

# Acknowledgments

This material is based upon work supported in part by ARO, SSC Pacific, IARPA
and DARPA under Contract Nos. W911NF-15-C-0227, N66001-15-C-4070,
2019-1902070006, and HR001120C0085.

Any opinions, findings and conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of
the ARO, SSC Pacific, IARPA and DARPA. Distribution Statement ``A'' (Approved
for Public Release, Distribution Unlimited).

Copyright © 2019-2022 Galois, Inc.
