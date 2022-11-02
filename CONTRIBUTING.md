This document is still a work in progress. More information will be added later.

# Tests
## Assets for Tests
Rather than reading files from tests (which will fail in CI due to a file not found error, due to our test caching setup), use `include_bytes!` or `include_str!` to instead copy the test asset that you want into the test binary at compile-time.

# Updating the pinned Rust version
Change the version in `rust-toolchain` to whichever pinned version you want.
Ideally, stick to stable pinned versions of rust.

You may need to `cd etc && niv update` in order for CI to recognize the new version of rust.
