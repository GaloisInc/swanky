//! Fixed parameters used across the entire protocol.
//!
//! This records all the fixed parameters we've chosen. Some of these may not be used directly in
//! the protocol execution, but we record them for posterity. We also fix the following parameters:
//! - The small-domain paramter $`S_\Delta`$ for the sVOLE functionality is set to $`\mathbb F_q`$
//!   where [$`q`$ is the VOLE field size](VOLE_SIZE_PARAM).
//! - The leakage parameter $`\mathcal L`$ for the sVOLE functionality is set to
//!   $`\{2^{S_\Delta}\}`$, which does not permit any leakage (see Baum et al., Section 5.1).
//!
//! The documentation references the shorthand names used in the paper; all these references are
//! to [Baum et al.](https://eprint.iacr.org/2023/996.pdf).

/// Computational security parameter ($`\lambda`$ in the paper).
pub const SECURITY_PARAM: usize = if cfg!(feature = "256bit") { 256 } else { 128 };

/// The field size ($`p`$ in the paper) in which the input circuit / polynomials
/// and the witness are defined.
///
/// Note that the ZK protocol for degree-2 polynomials from small-sized sVOLE defined in
/// Section 6.2 actually allows the input polynomials to be defined over an extension field
/// $`\mathbb F_{p^k}`$, for some $`k`$. For ease of implementation, we restrict the input
/// polynomials to be over $`\mathbb F_p`$.
#[allow(dead_code)]
pub const FIELD_SIZE: usize = 2;

/// The field size ($`r`$ in the paper) for the generated VOLEs, relative to [`FIELD_SIZE`].
///
/// Specifically, this defines the modulus for the extension field $`\mathbb F_q`$, where
/// $`q = p^r`$, for [the field size $`p`$](FIELD_SIZE).
///
/// This parameter needs to define a "small- to medium-sized" extension; other implementations
/// vary this from 7 to 11 (see [Baum et al., Section 7.2](https://eprint.iacr.org/2023/996.pdf))
pub const VOLE_SIZE_PARAM: usize = 8;

/// The repetition parameter ($`\tau`$ in the paper).
///
/// This determines the number of VOLE instances required for a secure protocol execution.
/// Guidance on selecting the repetition parameter can be found in
/// [the FAEST spec, Section 2.1.2](https://faest.info/faest-spec-v1.1.pdf).
///
/// This maintains the property that $`\lambda \approx r\tau`$, for the
/// [security parameter $`\lambda`$](SECURITY_PARAM) and the
/// [VOLE size parameter $`r`$](VOLE_SIZE_PARAM).
pub const REPETITION_PARAM: usize = if cfg!(feature = "256bit") { 32 } else { 16 };

#[cfg(not(feature = "256bit"))]
/// The binary field used throughout the protocol.
pub type FLambda = swanky_field_binary::F128b;
#[cfg(feature = "256bit")]
/// The binary field used throughout the protocol.
pub type FLambda = swanky_field_binary::F256b;

// FIXME (maybe): AesRng and Aes256Rng use standard `u128` counters. This results in
// architecture-specific endianness (usually little-endian). In contrast, FAEST 1.1 specifically
// calls out a big-endian counter on the PRG (v1.1 spec, Sec. 3.3), and FAEST increments the lower
// 32-bits in little-endian order using AddToLowerWord (v2 spec, Sec, 9.3.4) and tweaks the upper
// word. For interop (with whichever version we eventually target), it may be desirable to make this
// architecture-independent and match the spec.
#[cfg(not(feature = "256bit"))]
/// The RNG used throughout the protocol.
pub(crate) type AesRng = swanky_rng::AesRng;
#[cfg(feature = "256bit")]
/// The RNG used throughout the protocol.
pub(crate) type AesRng = swanky_rng::Aes256Rng;

#[cfg(not(feature = "256bit"))]
/// The XOF used throughout the protocol.
pub(crate) type ShakeXof = shake::Shake128;
#[cfg(feature = "256bit")]
/// The XOF used throughout the protocol.
pub(crate) type ShakeXof = shake::Shake256;
