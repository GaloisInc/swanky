# `swanky`: A suite of rust libraries for secure computation

`swanky` provides a suite of rust libraries for doing secure computation.

* `fancy-garbling`: Boolean and arithmetic garbled circuits.
  * `twopac`: Two-party garbled-circuit-based secure computation.
* `humidor`: Implementation of the Ligero zero knowledge proof system.
* `keyed_arena`: Bump allocator which allows for random access to its allocations.
* `inferno`: An implementation of the Limbo zero-knowledge proof system.
* `ocelot`: Oblivious transfer and oblivious PRFs.
* `popsicle`: Private-set intersection.
* `scuttlebutt`: Core primitives used by other `swanky` crates.
* `simple-arith-circuit`: Simple flat arithmetic circuit representation.

# A note on security

`swanky` is currently considered **prototype** software. Do not deploy it in
production, or trust it with sensitive data.

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

# Generating documentation

To generate documentation, please use `etc/rustdoc.py` in lieu of `cargo doc`.

# License

MIT License

# Contact

You can contact the `swanky` team at `swanky@galois.com`.

# Contributors

- Brent Carmer
- Ben Hamlin
- Alex J. Malozemoff
- Benoit Razet
- Marc Rosen

# Acknowledgments

This material is based upon work supported in part by ARO, SSC Pacific, IARPA
and DARPA under Contract Nos. W911NF-15-C-0227, N66001-15-C-4070,
2019-1902070006, and HR001120C0085.

Any opinions, findings and conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of
the ARO, SSC Pacific, IARPA and DARPA. Distribution Statement ``A'' (Approved
for Public Release, Distribution Unlimited).

Copyright © 2019-2022 Galois, Inc.
