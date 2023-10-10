---
title: "Swanky Contributing!"
---
This document is still a work in progress. More information will be added later.

:wave: Hello newcomer to Swanky! This document contains a lot of _stuff_ about our development process. Here are the most important sections for introducing you to Swanky:

1. [Code of Conduct](CODE_OF_CONDUCT.md)
2. [Goals of Swanky](#goals)
3. [Swanky Development Process](#swanky-development-process)

The first two sections of this document describes the _process_ of developing Swanky (e.g. how to go about adding a new feature, how to structure code review, etc.). The remainder of this document is about technical considerations when developing for Swanky.

In this document, we aim to emphasize _why_ we recommend the practices outlined in this document. If there's some development practice that doesn't have a good reason behind it, then we shouldn't be doing it!

Parts of Swanky currently diverge from these standards. We are working to help align all of Swanky with these standards.

[[_TOC_]]

# Goals
Swanky is a development platform for cryptographic research, intended for prototyping cryptographic protocols and implementation techniques. For Swanky to accelerate research and prototyping, it must provide a stable foundation that we can build on: it must be understandable, well-written, and well-designed. We'd rather our users be making progress instead of figuring out why some five-year-old library panics exclusively during the waxing gibbous moon. While there is some cost to developing Swanky-destined cryptography in such a manner, we believe that using software engineering practices to develop a new Swanky component will not only help streamline the development of this new component, but will also make it easier to re-use the component in the future. As they say, "one milligram of prevention is worth a centigram of cure."

Because Swanky is a research and prototyping platform, we prioritize work which is necessary to support those objectives over work to productionize the system. For example, Swanky does not currently implement protections against denial of service attacks. While these protections would be important in a production system, they aren't necessary to prove out ideas for our cryptographic research platform. Please reach out to us at <swanky@galois.com> if you're interested in using Swanky in a production setting.


# Swanky Development Process
## Goals of the development process
* **Distribute Swanky knowledge.** If a question comes up about a part of Swanky, we should be able to answer it, even if the person who originally wrote the code is on PTO and attending the 17th annual Diet Soda Taste Test Competition. We want to ensure that Swanky knowledge is distributed among the team, rather than localized in one person.
* **Professional Development.** Working on Swanky should be a learning opportunity, where people learn new skills and techniques.
* **Improve Code.** More eyes on both design and implementation will catch issues earlier, and avoid making the same mistakes over again, in addition to improving APIs and making the code easier to use.

## Start with a Design
Before you start writing code, start by planning it out, ideally with the rest of team. This is especially important for wide-reaching changes or core components—if your change is going to affect every user of Swanky, you should make sure that they're on board before you make the change.

For most cases, design docs should live as Gitlab issues, to allow people to comment on them. When the design is implemented, the content of the design document (not necessarily verbatim) should be included in the merge request, ideally as part of the rustdoc for the module.

## Merge Requests
_Every_ change to the Swanky git repo should be applied via a Merge Request. Before the change can be merged in, it must pass code review, and it must pass our Continuous Integration checks.

To quote Jonathan Daugherty:
> If a code review results in lots and lots of changes, that means early design review got missed. Code reviews shouldn't be hard; if they're hard, more [up-front work](#start-with-a-design) needed to happen.

### Changelog
We want Swanky to be a vehicle to support the external research community. In order to do so, we need to not only publish/open-source the Swanky codebase, but also release it in a way that will enable external users to depend on Swanky.

As we continue to develop Swanky, we change and break public APIs. When this happens, it's important that we notify both internal and external users of APIs that changed, and how they can migrate to new APIs. This information is documented in our changelog.

Merge requests which make breaking changes to APIs should also update the changelog to add the a new entry with the changes.

### Running CI Checks Locally
All MRs need to pass CI's checks. CI will, in addition to running Rust tests, also run a series of lints. It can be faster to run them locally (via `./swanky lint`), rather than waiting for CI to tell you that there was a failure.

### Git Branching Style
We follow the [Github Flow](https://docs.github.com/en/get-started/quickstart/github-flow) git branching workflow. `dev` is the main branch of the Swanky repo. In this workflow, you:
1. Branch off the target branch (typically `dev`)
2. Commit and push your changes to the branch
3. Open a [Merge Request](#merge-requests) from your branch to the target branch.
4. Have a [Code Review](#code-review)
5. Merge the branch in, and then delete the feature branch.

If a project demands it, you can merge into a project-specific branch, before merging the project-specific branch into `dev`, but it's preferable to just work off of `dev`.

### Branch Naming
We generate a lot of branches! In order to keep them tidy, it can be helpful to name branches like:

* **Feature Branches:** `feature/<name>`
* **Refactor Branches:** `refactor/<name>`
* **Experimental Branches:** `experimental/<name>`
* **Bugfix Branches:** `bugfix/<name>`

## `CODEOWNERS`
Each component[^what-is-a-component] of Swanky is owned by a team of at least _two_ people. This information is recorded in our [`CODEOWNERS`](https://docs.gitlab.com/ee/user/project/codeowners/) file.

[^what-is-a-component]: A component of Swanky ought to be one crate. However, there are some crates, like ocelot, which contain many different protocols and components. Until they get broken up into several different crates, different modules in ocelot might have distinct code owners.

The code owners are responsible for shepherding the components that they own, including:
* **Reviewing code which modifies their components.** Gitlab will automatically ask code owners to review any merge request which modifies code that they own.
* **Managing the health of the component.** This includes triaging issues which may impact the component.
* **Fielding questions about the component.** The code owners should be the resident experts on the components they own.
* **Documenting their component.** Someone should be able to read documentation to get fully up-to-speed on a component, without _needing_ to speak to one of its code owners. (We want code owners to be able to field questions because it's faster than _requiring_ everyone who has a question about a component to put in the leg work to learn about it.)

  We want to ensure that there's enough written down so that we can get new code owners up-to-speed, even if existing code owners are unavailable.

These responsibilities may consume hours. For example, if project A funds a 1,000 line code change to library B, project A could fund a code owner of library B for the 1-2 hours it would take to review the change.
## Code Review
The number one rule of code review is: "be kind!" Someone spent time writing the contribution that you are looking at. Code review provides a wonderful teaching/learning opportunity for everyone involved—treat it that way!

One goal of code review is to try to help avoid mistakes in code, or point out ways that it could be better. Beyond that, after a successful code review, reviewers should walk away with a deep understanding of the code that they just read. If none of the reviewers feel like they have a deep understanding of the code, it suggests that _something_ should be revisited: is the code confusing? Is it not the specialty of the reviewers?

After a successful code review, once the "Merge it In!" button has been pressed, the responsibility of the code should lie with the whole team. If the code has a bug in it, that's not the responsibility of the person who typed it; it's the responsibility of the whole team. On a healthy team, individuals aren't responsible for success or failure. The team should succeed or fail as a group, and code review is an important practice to make that a reality.

### Tips for Code Review
If you ask a reviewer to review too much code it can be overwhelming. Instead, break the code into many smaller pieces, that can be reviewed separately.

Ask questions of the code author in comments! If you have a question about the code, it can help indicate that code should be restructured or differently documented. At worst, it'll help your understanding!

See the [Galois-internal Code Review page for more details](https://confluence.galois.com/display/EN/Code+Reviews).

## AI Tools
Due to copyright concerns, we cannot accept _any_ contributions that were written, even in part, with AI tools (such as Github's Copilot). This extends to _any_ contribution to the repository, including source code, commit messages, documentation, etc.

# Language Choice
Swanky is written almost entirely in ([stable](#rust-version)) Rust.

Repository maintenance scripts, code generators, CI, or other tools which run at _compile-time_ are frequently written in Python (Rust is sometimes used instead).

For WebAssembly/webdev projects, some glue code is written in JavaScript. As of this writing (08/23) there isn't enough JavaScript code to warrant linters and formatters in CI for JS. If we end up doing much more web development in the future, we can set up formatters in CI and also switch to TypeScript.

In very rare cases, some Swanky code is written in C. Rust is preferred.
# Target Platform
Swanky primarily targets x86-64 Linux. As many Swanky developers use Macs, it should also run on both ARM and Intel Macs. Wasm32 is supported as a secondary target.

When writing Swanky code, it is _safe_ to assume that the target platform is little-endian and has the rust `std` library. It is not safe to assume that the target platform has 64-bit pointers.

Swanky should not depend on any dynamic libraries at runtime (all dependencies should be statically linked; this is standard for Rust code).

The Swanky build should not _require_ any tools other than the Rust compiler toolchain, `cargo`, and a C compiler/system linker.

In some cases, we may depend on external tools for [code generation](#code-generation). If this is the case, the external tool should not be required for a default build of Swanky. For example, you should only need to have the flatbuffer code generator tool installed if you make changes to Swanky's flatbuffer files.

The goal of this requirement is to make sure that it is easy for new users to get started with Swanky. It's much easier to say "all you need is Rust," than it is to start requiring additional tools on top.
# Repository Organization
Swanky is developed in a [monorepo](#versioning).

## One Feature Per Crate
We prefer to have many smaller crates rather than a few big crates. This strategy can drastically improve compilation times (especially for release builds). It also makes it easier for us to more precisely track the dependencies of Swanky components.

For example, rather than having a single crate for all things oblivious transfer, we'd prefer to have a `swanky-ot-traits` crate for the core Oblivious Transfer traits, and then a `swanky-ot-*` crate for each OT protocol implementation.

The script `./swanky new-crate` makes it easy to create a new crate and register it the workspace's `Cargo.toml` file.
 
 Use it like:
 ```
# Create a crate named swanky-ot-kos
$ ./swanky new-crate swanky-ot-kos
```
## Cargo Features
[Cargo features](https://doc.rust-lang.org/cargo/reference/features.html) allow for conditional compilation of Rust code.

We should _avoid_ defining Cargo features whenever possible! Features are extremely hard to test, since we'd need to test all combinations of features.

### How to avoid defining a Feature
#### Optionally Compile a Module
For code that would look like:
```rust
#[cfg(feature = "cool_module")]
pub mod cool_module;
```
Rather than defining a Cargo feature, it's preferable to create a [new crate](#one-feature-per-crate) with the optional functionality, instead.
#### Optionally Implement a Trait
For example, maybe you want to implement the [`num::Zero`](https://docs.rs/num/latest/num/trait.Zero.html) trait on a type you define, but you don't want to pull in the `num` dependency in all cases.

_With_ features (i.e. the **EVIL** way), the code would look like:
```rust
#[cfg(feature = "num")]
impl num::Zero for MyFunIntegerType { /* ... */ }
```
The better way is to unconditionally depend (i.e. without a Cargo feature) on the [`num_traits`](https://docs.rs/num-traits/latest/num_traits/identities/trait.Zero.html) crate. This crate is small since it _only_ contains the core traits of the `num` ecosystem, and so depending on it won't bloat compile times, while at the same time avoiding the definition of a new crate feature.

This technique isn't specific to the `num` ecosystem, either. Many Rust libraries provide an explicit `_traits`-style crate.
## Crate Layout
All crates should (note: as of this writing, this isn't true):
* live in the `crates/` directory. If the crate lives in a subdirectory of the `crates/` directory, the directory structure must match the name of the crate (to make it easy to find the crate). For example `swanky-ot-kos` might live in `crates/ot-kos` or `crates/ot/kos`, but it shouldn't live in `crates/kos`.
* be named starting with the `swanky-` prefix. This makes it easy to determine which crates come from Swanky, and which crates are external dependencies.
# Documentation
Swanky APIs should be documented using [rustdoc](https://doc.rust-lang.org/rustdoc/index.html).

Documentation can be generated using [`cargo doc`](https://doc.rust-lang.org/cargo/commands/cargo-doc.html) so, for example `cargo doc --workspace --no-deps --open` will open Swanky documentation in your web browser.

Swanky enables several Markdown extensions: [LaTeX math with KaTeX](https://katex.org/) and diagrams with [Mermaid](http://mermaid.js.org/).

````markdown
Here's some inline math: $`x^2`$

And some block math:

```math
\frac{a}{b}
```

And a diagram!

```mermaid
graph TD;
    A-->B;
    A-->C;
    B-->D;
    C-->D;
```
````

# Code Formatting
In the Swanky repo, Rust code is automatically formatted with [rustfmt](https://github.com/rust-lang/rustfmt), and [black](https://github.com/psf/black) and [isort](https://pycqa.github.io/isort/) for Python code. CI will reject any code which isn't properly formatted.

We enforce code formatting practices (in CI) to try to keep git patches as meaningful as possible. It's easier to review a merge request if the only changes are changed intended by the author, and not changes to the tab width because of how the author configured their code editor.

You can autoformat Rust code with `cargo fmt` or format all code with `./swanky fmt`.
# Dependencies
## Version Pinning
We commit _exact_ versions of all dependencies into the Swanky repository. This ensures that _every_ user and developer of Swanky gets the identical dependencies, avoiding issues with dependency version mismatch.

CI will ensure that the checked-in version files (`Cargo.lock` and `rust-toolchain`) are a valid snapshot of our dependencies.

Because our focus is on cryptographic research, and not shipping a production library, we do not test Swanky against versions of dependencies or versions of Rust other than those that we've pinned.
## Rust Version
We pin a stable version of the Rust toolchain in the `rust-toolchain` file. We only use stable Rust features and do not build off of nightly. Our MSRV (Minimum Supported Rust Version) is the version that we have pinned. We try to update the pinned Rust version as new Rust versions are released.
# Cargo Workspace Inheritance
To ensure uniformity across Cargo metadata, `swanky` employs [Cargo's workspace inheritance functionality](https://betterprogramming.pub/workspace-inheritance-in-rust-65d0bb8f9424).
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

CI will enforce the use of workspace inheritance.
# Tests
All code in Swanky _should_ be tested via Rust tests. Ideally, tests would test both valid input (the happy path) and invalid inputs.

When testing pure functions, we like to use property-based-testing from [the `proptest` crate](https://proptest-rs.github.io/proptest/intro.html). This crate uses will test a function against random values, to see if its invariants hold. This is preferable (where applicable) to writing explicit unit test cases, since it is easier to maintain, and more directly encodes assumptions on test inputs.
## Assets for Tests
Rather than reading files from tests (which will fail in CI due to a file not found error, due to our test caching setup), use `include_bytes!` or `include_str!` to instead copy the test asset that you want into the test binary at compile-time.

# Panicking
[￼`panic!`￼](https://doc.rust-lang.org/std/macro.panic.html)/[￼`unwrap`￼](https://doc.rust-lang.org/std/result/enum.Result.html#method.unwrap) (and friends) should only be used to report _internal_ errors (i.e. assertion failures) in the program. They should not be used as a general error handling technique (expect for tests and build scripts). If a program panics, that means that it has a bug.

The use of asserts can make a program more robust and easier to debug. It's much easier to debug a program with a failed assertion that yells "the problem is here," than it is to debug a program that reports no problems at all. Beyond that, assertions can be used to document the programmer's assumptions about the code in a way that's both human-readable and computer-checkable.

Rust provides two kinds of asserts [`assert!`](https://doc.rust-lang.org/std/macro.assert.html) and [`debug_assert!`](https://doc.rust-lang.org/std/macro.debug_assert.html). `assert!(cond)` will, for all build of the program, panic if `cond` is false. `debug_assert!(cond)` will only check (and panic if `cond`is false) for debug builds.

Rust also provides helpers [`assert_eq!`](https://doc.rust-lang.org/std/macro.assert_eq.html) (as well as not equal and `debug_` variants) which is roughly equivalent to `assert!(a == b, "{a:?} == {b:?})`. `assert_eq!` should be preferred over `assert!(a == b)`, because it prints out the inputs on panic.

We (except in extreme cases) avoid the use of [`std::panic::catch_unwind`](https://doc.rust-lang.org/std/panic/fn.catch_unwind.html) in Swanky, which makes it easier to reason about our code.

## Examples of Good use of Panic
```rust
#[test]
fn my_test() {
    let (a, b) = UnixStream::pair().unwrap();
}

fn decode_le_ints(x: &[u8]) -> impl Iterator<Item = u32> + '_ {
    x.chunks_exact(4).map(|chunk| {
        // Because chunks_exact(4) only returns slices of size 4, this shouldn't panic.
        u32::from_le_bytes(<[u8; 4]>::try_from(chunk).unwrap())
    })
}

fn write_bytes_slow(my_buffer: &mut Buffer, data: &[u8]) -> eyre::Result<()> {
    my_buffer.force_flush()?;
    // Flushing should've emptied the buffer.
    debug_assert_eq!(my_buffer.write_buffer.len(), 0);
    my_buffer.copy_from(data);
}

// Because this function has documented that the haystack must be sorted,
// it becomes the responsiblity of this caller to satisfy this
// precondition. Possibly by calling .sort() on haystack before calling
// this function. Or maybe haystack is generated in such a way that the
// caller _knows_ that it will be already sorted.
/// # Panics
/// This function may panic if the input array isn't correctly sorted.
fn swanky_binary_search(haystack: &[u32], needle: u32) -> Option<usize> {
    debug_assert!(check_sorted(haystack));
    // ...
}
```
## Examples of Poor use of Panic
```rust
fn main() -> eyre::Result<()> {
    let numbers: Vec<u32> =
        serde_json::from_str(
            &std::fs::read_to_string("test.json")
             .context("Opening 'test.json'")
        ).context("Decoding 'test.json'")?;
    // This is incorrect! swanky_binary_search (see above) requires that
    // numbers is in sorted order, and it may panic if that's not true.
    // In order to be correct, this program must either sort numbers, or
    // validate that numbers is in sorted order before this callsite.
    let out = swanky_binary_search(&numbers, 75);
}

fn main() {
    // If there's a DNS failure, or if example.com is down, or some other
    // problem _outside of the control of the program author_, this
    // program will panic.
    let tcp_stream = TcpStream::connect("example.com:80").unwrap();
    // ...
}
```

# Unsafe Code
Unsafe code should be avoided if possible., but sometimes it is necessary to use `unsafe` code, either for performance reasons, or maybe to interface with some [FFI](https://en.wikipedia.org/wiki/Foreign_function_interface).

For most operations, the Rust compiler will prove that, for example, the program won't segfault. However, there are some operations where the Rust compiler can't guarantee that all the requirements of an operation have been met, and that unsoundness could result if these requirement have been violated.

The `unsafe` keyword tells the Rust compiler that the programmer will take responsibility for ensuring these preconditions have been met. _Each_ `unsafe` block should document how it's meeting the preconditions of the operations contained within.

`unsafe` code should _almost never_ be mixed with business logic to let you reason about the correctness of `unsafe` code in isolation. Instead, prefer writing a safe wrapper which can contain the unsafe code wherever possible.

See [the sample implementation of `swap`](https://doc.rust-lang.org/std/ptr/fn.read.html#examples) as a good example of both of these principles.

# Constant-Time Operations
Swanky code that operates on private values should use constant-time operations to avoid [timing attacks](https://en.wikipedia.org/wiki/Timing_attack). We use the [subtle crate](https://docs.rs/subtle/latest/subtle/)
to execute constant-time operations.

# Allocations
Invoking the memory allocator to `malloc()` and `free()` memory takes a lot of computational resources. Reducing memory allocation can frequently produce large speedups in our benchmarks.

To that end, APIs should be written to avoid _requiring_ the use of the memory allocator. For example:

```rust
fn range(n: usize) -> Vec<usize> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        out.push(i);
    }
    out
}
```

This function _requires_ a new allocation each time it's invoked. It could be rewritten in any of the following ways to eliminate the memory allocation.

If the caller provides the destination buffer, its allocation can be re-used across calls.
```rust
fn range(n: usize, dst: &mut Vec<usize>) {
    dst.reserve(n);
    for i in 0..n {
        dst.push(i);
    }
}
fn range_use_example() {
    let mut buf = Vec::new();
    for i in 0..15 {
        // This sets buf.len() to 0, but it doesn't free the allocation, so it
        // can be re-used in the next iteration.
        buf.clear();
        range(i, &mut buf);
        for j in buf.iter() {
        	println!("{j}");
        }
    }
}
```

Alternatively, `range` could return an `Iterator`, which doesn't require that its outputs be stored in a buffer at all. This approach lets the compiler interleave the execution of `range` with its caller, providing a performance boost in some cases (in some cases, using an explicit buffer is faster).

```rust
// impl Iterator doesn't allocate anything.
fn range(n: usize) -> impl Iterator<Item = usize> {
	0..n
}
```
