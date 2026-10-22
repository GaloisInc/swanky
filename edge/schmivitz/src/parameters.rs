//! Fixed parameters used across the entire protocol.
//!
//! This records all the fixed parameters we've chosen. Some of these may not be used directly in
//! the protocol execution, but we record them for posterity. We also fix the following parameters:
//! - The small-domain paramter $`S_\Delta`$ for the sVOLE functionality is set to $`\mathbb F_q`$
//!   where [$`q`$ is the VOLE field size](VoleSizeParam).
//! - The leakage parameter $`\mathcal L`$ for the sVOLE functionality is set to
//!   $`\{2^{S_\Delta}\}`$, which does not permit any leakage (see Baum et al., Section 5.1).
//!
//! The documentation references the shorthand names used in the paper; all these references are
//! to [Baum et al.](https://eprint.iacr.org/2023/996.pdf).

use hybrid_array::typenum::{PartialQuot, Prod, Sub1, Sum, U2, U3, U6, U8, U16, Unsigned};
use hybrid_array::{Array, ArraySize};
use rand::{CryptoRng, SeedableRng};
use shake::{ExtendableOutput, Shake128, Shake256};
use swanky_field::{FiniteField, IsSubFieldOf};
use swanky_field_binary::{F2, F8b, F128b, F256b};
use swanky_rng::{Aes128Rng, Aes256Rng};
use swanky_serialization::CanonicalSerialize;

use crate::vole::crypto_primitives::IV;

/// Finite field, crypto primitives, and constants associated with a Schmivitz for a given security
/// parameter.
pub trait Params: Clone + Copy + core::fmt::Debug + Default + 'static {
    /// The field used for VOLE tags and proof arithmetic. The field size must be at least
    /// $`2^\lambda`$, where $`\lambda`$ is the security parameter (a.k.a.,
    /// [`Params::SecurityParam`]).
    type FLambda: FiniteField<PrimeField = F2>
        + CanonicalSerialize<ByteReprLen = Self::SecurityParamBytes>;

    /// The RNG used throughout the protocol.
    type Prng: CryptoRng + SeedableRng;

    /// The XOF used throughout the protocol.
    type Xof: ExtendableOutput + Default;

    /// The field size ($`p`$ in the paper) in which the input circuit / polynomials
    /// and the witness are defined.
    ///
    /// Note that the ZK protocol for degree-2 polynomials from small-sized sVOLE defined in
    /// Section 6.2 actually allows the input polynomials to be defined over an extension field
    /// $`\mathbb F_{p^k}`$, for some $`k`$. For ease of implementation, we restrict the input
    /// polynomials to be over $`\mathbb F_p`$.
    type SecurityParam: ArraySize;

    /// The size of an [`FLambda`] element in bytes.
    type SecurityParamBytes: ArraySize;

    /// The repetition parameter ($`\tau`$ in the paper).
    ///
    /// This determines the number of VOLE instances required for a secure protocol execution.
    /// Guidance on selecting the repetition parameter can be found in
    /// [the FAEST spec, Section 2.1.2](https://faest.info/faest-spec-v1.1.pdf).
    ///
    /// This maintains the property that $`\lambda \approx r\tau`$, for the
    /// [security parameter $`\lambda`$](SecurityParam) and the
    /// [VOLE size parameter $`r`$](VoleSizeParam).
    type RepetitionParam: ArraySize;

    /// The size of a `Com`mitment in bytes.
    type ComBytes: ArraySize;

    /// The size of a `Chall1` in bytes.
    type Chall1Bytes: ArraySize;

    /// The size of a `Chall2` in bytes.
    type Chall2Bytes: ArraySize;

    /// The size of an `H3` digest in bytes.
    type H3Bytes: ArraySize;

    /// The number of `Corrections`, $`\tau - 1`$.
    type CorrectionsCount: ArraySize;

    /// $`\lambda + B`$, where $`B`$ is the padding parameter.
    type SecurityParamPadded: ArraySize;

    /// $`r\tau`$: the number of VOLEs used to mask the aggregated commitments.
    type MaskLength: ArraySize;

    /// Construct the [`Params::Prng`] from a seed and an initialization vector.
    fn new_prng_with_iv(seed: &Array<u8, SecurityParamBytes<Self>>, iv: IV) -> Self::Prng;

    /// Construct the [`Params::Prng`] from a seed alone.
    fn new_prng(seed: &Array<u8, SecurityParamBytes<Self>>) -> Self::Prng;

    /// Homomorphically lift $`\lambda`$ [`F2`] values into a [`Params::FLambda`].
    fn f2_form_superfield(bits: &Array<F2, SecurityParam<Self>>) -> Self::FLambda;

    /// Multiply a [`Params::FLambda`] by an [`F2`] from its prime subfield.
    fn f2_scale(bit: F2, x: Self::FLambda) -> Self::FLambda;

    /// Embed an [`F2`] into [`Params::FLambda`] as an element of its prime subfield.
    fn f2_embed(bit: F2) -> Self::FLambda;

    /// Lift a $`\tau`$-length vector of [`F8b`] VOLE tags into a single [`FLambda`] element.
    ///
    /// Each of the $`\tau`$ small-field VOLE instances contributes one [`F8b`] tag per correlation
    /// (see [`crate::vole::RandomVoleV::witness_voles()`]), but the degree-2 proof of Baum et al.
    /// Figure 7 works over $`\mathbb F_{2^\lambda}`$ and needs them as single elements.
    ///
    /// Note that this does *not* require an [`F8b`] ring homomorphism. Any $`\mathbb F_2`$-linear
    /// bijection is a valid choice here. The VOLE relation $`q = u \Delta + v`$ has $`u \in \mathbb
    /// F_2`$, so lifting each of $`u`$, $`v`$, $`q`$ and $`\Delta`$ with the same map preserves it;
    /// every later operation happens entirely inside [`FLambda`], identically on the prover's and
    /// the verifier's side.
    fn f8_linear_bijection(tags: &Array<F8b, Self::RepetitionParam>) -> Self::FLambda;
}

/// Convenience type to access [`Params::SecurityParam`].
pub type SecurityParam<P> = <P as Params>::SecurityParam;

/// Convenience type to access [`Params::SecurityParamBytes`].
pub(crate) type SecurityParamBytes<P> = <P as Params>::SecurityParamBytes;

/// The field size ($`p`$ in the paper) in which the input circuit / polynomials
/// and the witness are defined.
///
/// Note that the ZK protocol for degree-2 polynomials from small-sized sVOLE defined in
/// Section 6.2 actually allows the input polynomials to be defined over an extension field
/// $`\mathbb F_{p^k}`$, for some $`k`$. For ease of implementation, we restrict the input
/// polynomials to be over $`\mathbb F_p`$.
pub type FieldSize = U2;

/// The field size ($`r`$ in the paper) for the generated VOLEs, relative to [`FieldSize`].
///
/// Specifically, this defines the modulus for the extension field $`\mathbb F_q`$, where
/// $`q = p^r`$, for [the field size $`p`$](FieldSize).
///
/// This parameter needs to define a "small- to medium-sized" extension; other implementations
/// vary this from 7 to 11 (see [Baum et al., Section 7.2](https://eprint.iacr.org/2023/996.pdf))
pub type VoleSizeParam = U8;

/// Parameter used for padding for the security of the consistency check
pub type B = U16;

/// Convenience type to access [`Params::RepetitionParam`].
pub type RepetitionParam<P> = <P as Params>::RepetitionParam;

/// Convenience type to access [`Params::ComBytes`].
pub(crate) type ComBytes<P> = <P as Params>::ComBytes;

/// Convenience type to access [`Params::Chall1Bytes`].
pub(crate) type Chall1Bytes<P> = <P as Params>::Chall1Bytes;

/// Convenience type to access [`Params::Chall2Bytes`].
pub(crate) type Chall2Bytes<P> = <P as Params>::Chall2Bytes;

/// Convenience type to access [`Params::H3Bytes`].
pub(crate) type H3Bytes<P> = <P as Params>::H3Bytes;

/// Convenience type to access [`Params::CorrectionsCount`].
pub(crate) type CorrectionsCount<P> = <P as Params>::CorrectionsCount;

/// Convenience type to access [`Params::SecurityParamPadded`].
pub type SecurityParamPadded<P> = <P as Params>::SecurityParamPadded;

/// Convenience type to access [`Params::MaskLength`].
pub type MaskLength<P> = <P as Params>::MaskLength;

/// Convenience type to access [`Params::FLambda`].
pub type FLambda<P> = <P as Params>::FLambda;

/// Convenience type to access [`Params::Prng`].
pub(crate) type Prng<P> = <P as Params>::Prng;

/// Convenience type to access [`Params::Xof`].
pub(crate) type Xof<P> = <P as Params>::Xof;

macro_rules! declare_binary_extension_params {
    ( $(#[$doc:meta])*
        $name:ident {
            field = $flambda:ty,
            prng = $prng:ty,
            xof = $xof:ty $(,)?
        }
    ) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

        impl Params for $name {
            type FLambda = $flambda;
            type Prng = $prng;
            type Xof = $xof;

            type SecurityParam = <$flambda as FiniteField>::NumberOfBitsInBitDecomposition;
            type SecurityParamBytes = <$flambda as CanonicalSerialize>::ByteReprLen;

            // NOTE: We use [`PartialQuot`] here rather than [`hybrid_array::typenum::Quot`] to
            // ensure that [`VoleSizeParam`] divides [`SecurityParam`].
            type RepetitionParam = PartialQuot<Self::SecurityParam, VoleSizeParam>;

            type ComBytes = Prod<Self::SecurityParamBytes, U2>;
            type Chall1Bytes = Prod<Self::SecurityParamBytes, U6>;
            type Chall2Bytes = Sum<Prod<Self::SecurityParamBytes, U3>, U8>;
            type H3Bytes = Sum<Self::SecurityParamBytes, U16>;
            type CorrectionsCount = Sub1<Self::RepetitionParam>;
            type SecurityParamPadded = Sum<Self::SecurityParam, B>;
            type MaskLength = Prod<Self::RepetitionParam, VoleSizeParam>;

            fn new_prng_with_iv(seed: &Array<u8, SecurityParamBytes<Self>>, iv: IV) -> Self::Prng {
                Self::Prng::from_seed_and_iv(seed.0.into(), u128::from_le_bytes(iv))
            }

            fn new_prng(seed: &Array<u8, SecurityParamBytes<Self>>) -> Self::Prng {
                Self::Prng::from_seed(seed.0.into())
            }

            fn f2_form_superfield(bits: &Array<F2, SecurityParam<Self>>) -> Self::FLambda {
                F2::form_superfield(bits)
            }

            fn f2_scale(bit: F2, x: Self::FLambda) -> Self::FLambda {
                bit * x
            }

            fn f2_embed(bit: F2) -> Self::FLambda {
                bit.into()
            }

            /// We use the map that reads the $`\tau`$ tags as the low-to-high polynomial coefficients of the
            /// result, which makes the lift a byte copy: byte `i` of an [`FLambda`] holds exactly the
            /// coefficients of the `i`th [`F8b`].
            ///
            /// Note that this is deliberately *not* the $`\mathbb F_{2^8}`$-tower isomorphism that
            /// [`swanky_field::IsSubFieldOf`] provides via `F8b::form_superfield`. That map is additionally a
            /// *ring* homomorphism, which this protocol never needs, and it costs a change-of-basis matrix
            /// multiply per lift rather than a copy.
            fn f8_linear_bijection(tags: &Array<F8b, Self::RepetitionParam>) -> Self::FLambda {
                // Since `REPETITION_PARAM * VOLE_SIZE_PARAM == SECURITY_PARAM`, there is exactly one tag byte
                // per byte of an `FLambda`.
                let bytes: Array<u8, Self::RepetitionParam> = tags.clone().map(|tag| tag.to_bytes()[0]);
                Self::FLambda::from_bytes(&bytes).expect("unreachable: RepetitionParam must equal ByteReprLen")
            }
        }

        /// NOTE: [`SecurityParamBytes`] must equal $`\lceil \lambda / 8 \rceil`$.
        const _: () = assert!(
            SecurityParamBytes::<$name>::USIZE * 8 == SecurityParam::<$name>::USIZE
        );

        /// NOTE: [`RepetitionParam`] must equal [`SecurityParamBytes`] in order to use our [`F8b`]
        /// linear bijection. This is always true, since we hard-code [`VoleSizeParam`] to [`U8`].
        /// If this changes in  future implementation, this assert will fail.
        const _: () = assert!(
            RepetitionParam::<$name>::USIZE == SecurityParamBytes::<$name>::USIZE
        );
    }
}

declare_binary_extension_params! {
    /// Parameters using a binary extension field and providing 128 bits of security.
    Binary128Bit {
        field = F128b,
        prng = Aes128Rng,
        xof = Shake128,
    }
}

declare_binary_extension_params! {
    /// Parameters using a binary extension field and providing 256 bits of security.
    Binary256Bit {
        field = F256b,
        prng = Aes256Rng,
        xof = Shake256,
    }
}
