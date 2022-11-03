This document is still a work in progress. More information will be added later.

# Cargo Workspace Inheritance
To ensure unifomrity across Cargo metadata, `swanky` employs [Cargo's workspace inheritance functionality](https://betterprogramming.pub/workspace-inheritance-in-rust-65d0bb8f9424).
This functionality lets us set a common set of metadata (such as version, license, author) in the root `Cargo.toml` file, and have it automatically applied across all of our crates.
Similarly, we also use workspace inheritance to specify a single version of our dependencies in the root `Cargo.toml` file.

To use Cargo workspace inheritance, add to your `Cargo.toml` file:
```toml
[package]
authors.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true
version.workspace = true
```

Use dependencies like:
```toml
num = { workspace = true, default-features = true }
vector2d.workspace = true
rand = { workspace = true, features = [ "log" ] }
```

CI will enforce the use of workspace in inheritance.

# Tests
## Assets for Tests
Rather than reading files from tests (which will fail in CI due to a file not found error, due to our test caching setup), use `include_bytes!` or `include_str!` to instead copy the test asset that you want into the test binary at compile-time.

# Updating the pinned Rust version
Change the version in `rust-toolchain` to whichever pinned version you want.
Ideally, stick to stable pinned versions of rust.

You may need to `cd etc && niv update` in order for CI to recognize the new version of rust.
