# `vectoreyes`

`vectoreyes` (_coincidentally_ pronounced like "vectorize") is a (almost entirely) safe library for performing vectorized operations.

The raw intrinsics which vectoreyes uses under the hood are hard to use correctly. It's easy to mix-up, for example `_mm256_srai_epi32` with `_mm256_srli_epi32` or even `_mm256_slli_epi32`. Vectoreyes provides an interface that is much easier to use.

# Platform Support
At the moment, vectoreyes supports to platforms: AVX2 and Scalar. If you are not compiling/running swanky on a processor that supports AVX2, vectoreyes will fall back to executing all operations on scalar. The scalar fallbacks are tested against the vectorized backend. In addition, the code of the scalar fallbacks are included in the documentation to help explain operation functions perform.

Not every microarchitecure that supports AVX2 has the same performance characteristics. At the moment, we care about 3 microarchitecures: Skylake (what my laptop runs), Skylake-X (what `forge.galois.com` runs), and Cascade Lake (what `planetarium` VMs run).

These microarchitectures are treated with special care in vectoreyes. In particular, we adjust the AES encryption pipeline size based on the latency of their AES encryption instructions.

As more intrinsics get stabilized in Rust, and as we get access to newer hardware (Ice Lake, in particular, has some new instructions which ought to speed up our random number generation by a factor of 4), I anticipate that both the vectoreyes APIs and internals will evolve.

`vectoreyes` should be used instead of raw `std::arch::x86_64` intrinsics. If an intrinsic is missing, open a merge reqeust to add it!

# Generated Code
While vectoreyes initially started as a pile of macros and traits, it was easier to develop by generating code using Python (and the jinja2 templating language). The generated code is checked in to avoid the dependency on Python at build-time.

# External Resources

## `vectoreyes/src/codegen/intel-intrinsics-3.4.5.xml.xz`
This file is provided by Intel and contains information on each of the platform intrinsics. I could not find any licensing on it. However, it seems to be pretty regularly included in code repos (e.g. [by rust](https://github.com/rust-lang/stdarch/blob/master/crates/stdarch-verify/x86-intel.xml)).

# Documentation
The generated code which is checked in _does not_ use data from https://uops.info/ to enhance the documentation.
If you want to see additional performance information in the vectoryes documentation, download an `instructions.xml` file from [the uops.info website](https://uops.info/xml.html), and set the `UOPS_INFO_XML` to the path of the XML file.