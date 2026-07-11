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
pub const SECURITY_PARAM: usize = 128;

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
pub const REPETITION_PARAM: usize = 16;

// The prime stuff
/// The number of GGM tree repetition
pub const TAU: usize = 16;
/// Number of instances of small-∆ VOLE
pub const NC: usize = TAU;
/// Dimension of linear code C
pub const KC: usize = 8; // Kc should be power of 2, such that Nc <= 2*Kc (comes from the 2*k^th root of unity thingy in the RS encoding)

/// Larger bit length for small-∆ VOLE
pub const D0: usize = 8;
/// Smaller bit length for small-∆ VOLE
pub const D1: usize = 8;

/// Larger GGM tree repetition
pub const T0: usize = (SECURITY_PARAM + (TAU - 1)) / TAU;
/// Smaller GGM tree repetition
pub const T1: usize = SECURITY_PARAM / TAU;

/// Sizes of ∆ space for small-∆ VOLE
pub const N0: usize = 1 << D0;
/// Sizes of ∆ space for small-∆ VOLE
pub const N1: usize = 1 << D1;

/// The maximum degree of the VOLE proofs
pub const MAX_DEG: usize = 2;

/// Maximum supported bit length for Fields
pub const MAX_BIT_LEN: usize = 512;
/// size of one u64 taking one limb of the Field element
pub const ONE_LIMB: usize = 64;
/// Maximum limbs needed
pub const MAX_LIMBS_SUPPORTED: usize = MAX_BIT_LEN / ONE_LIMB;
