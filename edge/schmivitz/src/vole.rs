//! Defines the overarching trait for non-interactive VOLE and includes various implementations.
//!
//! Expected implementations:
//! - Dummy insecure version for non-blocking development
//! - Secure version as described in FAEST spec and paper
//!

pub(crate) mod insecure;

use crypto_primitives::Chall3;
use generic_array::GenericArray;
use hybrid_array::Array;
use merlin::Transcript;
use rand::CryptoRng;
use swanky_error::Result;
use swanky_field_binary::{F2, F8b};
use swanky_serialization::CanonicalSerialize;

use crate::parameters::{FLambda, MaskLength, Params, RepetitionParam, SecurityParamBytes};

// Exposing these modules for benchmarking at the moment.
pub(crate) mod all_but_one_vc;
pub(crate) mod commit_reconstruct;
pub(crate) mod consistency_check;
pub(crate) mod convert_to_vole;
pub(crate) mod crypto_primitives;
pub mod functionality;
pub(crate) mod integration;

/// Lift a $`\tau`$-length vector of [`F8b`] VOLE tags into a single [`FLambda`] element.
///
/// Each of the $`\tau`$ small-field VOLE instances contributes one [`F8b`] tag per correlation
/// (see [`RandomVoleV::witness_voles()`]), but the degree-2 proof of Baum et al. Figure 7 works
/// over $`\mathbb F_{2^\lambda}`$ and needs them as single elements.
///
/// Any $`\mathbb F_2`$-linear bijection is a valid choice here. The VOLE relation
/// $`q = u \Delta + v`$ has $`u \in \mathbb F_2`$, so lifting each of $`u`$, $`v`$, $`q`$ and
/// $`\Delta`$ with the same map preserves it; every later operation happens entirely inside
/// [`FLambda`], identically on the prover's and the verifier's side.
///
/// We use the map that reads the $`\tau`$ tags as the low-to-high polynomial coefficients of the
/// result, which makes the lift a byte copy: byte `i` of an [`FLambda`] holds exactly the
/// coefficients of the `i`th [`F8b`].
///
/// Note that this is deliberately *not* the $`\mathbb F_{2^8}`$-tower isomorphism that
/// [`swanky_field::IsSubFieldOf`] provides via `F8b::form_superfield`. That map is additionally a
/// *ring* homomorphism, which this protocol never needs, and it costs a change-of-basis matrix
/// multiply per lift rather than a copy.
pub(crate) fn lift<P: Params>(tags: &Array<F8b, RepetitionParam<P>>) -> FLambda<P> {
    // Since `REPETITION_PARAM * VOLE_SIZE_PARAM == SECURITY_PARAM`, there is exactly one tag byte
    // per byte of an `FLambda`.
    let bytes: Array<u8, RepetitionParam<P>> = tags.clone().map(|tag| tag.to_bytes()[0]);

    // This unwrap is safe because the length is fixed and deserializing a binary field element
    // cannot fail.
    FLambda::<P>::from_bytes(GenericArray::<u8, SecurityParamBytes<P>>::from_slice(
        bytes.as_slice(),
    ))
    .unwrap()
}

/// Trait capturing the interface of serializable/deserializable Decommitment
pub trait DecommitmentSerde {
    /// For now only a only a proof size estimate until we get full ser/de capabilities.
    fn proof_size_estimate(&self) -> usize;
}

/// The prover's secret must have a bytes-wise representation.
///
/// Note: Ideally this would not require new allocation into a `Vec` but
/// I can't figure out how to do it for our secret type.
pub trait AsSecretBytes {
    /// Byte-wise representation of the secret.
    fn as_bytes(&self) -> Vec<u8>;
}

/// Methods for a prover to create and decommit to an instance of VOLE.
///
/// It's tailored to the specific use case of the VOLE-in-the-head paper[^vole], including
/// hardcoding some lengths and field sizes based on the [fixed parameters](crate::parameters)
/// and generally having an API that corresponds to the components and uses of
/// random VOLEs in Figure 7 of the paper, rather than the generic usage.
/// One notable difference is that the paper uses 1-indexing to refer to specific VOLE instances,
/// but this implementation uses 0-indexing.
///
/// ⚠️ Beyond the API limitations, this trait cannot be used in an arbitrary protocol that requires
/// a non-interactive VOLE. Specifically, the non-interactive decommitment step is equivalent to a
/// verifier revealing its choice bits (here, simulated using fiat-Shamir) to the prover; this
/// means that any protocol using this functionality must ensure that the verifier only obtains
/// their decommits at the end of the protocol, after the prover has completed all their operations
/// (see Baum et al.[^vole], Section 3.2 for more detail).
///
/// [^vole]: Carsten Baum, Lennart Braun, Cyprien Delpech de Saint Guilhem, Michael Klooß,
/// Emmanuela Orsini, Lawrence Roy, and Peter Scholl. [Publicly Verifiable Zero-Knowledge and
/// Post-Quantum Signatures from VOLE-in-the-head](https://eprint.iacr.org/2023/996). 2023.
#[allow(dead_code)]
pub trait RandomVoleP
where
    Self: Sized,
{
    /// The protocol parameters this VOLE is instantiated at.
    type Params: Params;

    /// Decommitment information for the random VOLE.
    ///
    /// This must only contain information that is safe to be sent to the verifier at the end of
    /// the protocol.
    type Decommitment: DecommitmentSerde;

    /// Type of the challenge generated when creating the VOLEs.
    type VoleChallenge;

    /// Create a set of random VOLEs.
    ///
    /// This is particular to the protocol by Baum et al., so the total number of VOLEs created
    /// should be $`\ell + r\tau`$, where $`\ell`$ is the `extended_witness_length`;
    /// $`r`$ is the [`VoleSizeParam`](crate::parameters::VoleSizeParam); and $`\tau`$ is the [`RepetitionParam`].
    ///
    /// The [`Transcript`] passed here must already incorporate all public information known to
    /// both parties at the beginning of the proof, including
    /// the public [`parameters`](crate::parameters);
    /// some representation of the circuit being proven;
    /// any public inputs to the circuit; and
    /// any external context provided at the application level.
    /// Internally, it must incorporate any additional public parameters defined by this
    /// instantiation of `RandomVole` before generating the [`RandomVoleP::VoleChallenge`].
    ///
    /// The `secret_stream` should incorporate private information known only to the verifier.
    /// It can be used to generate randomness, IVs, and other proof-specific fields.
    fn create<Secret: AsSecretBytes>(
        extended_witness_length: usize,
        transcript: &mut Transcript,
        secret: &Secret,
        rng: &mut impl CryptoRng,
    ) -> (Self, Self::VoleChallenge);

    /// Get the total number of VOLE correlations supported by this random VOLE instance.
    ///
    /// This should be $`\ell + r\tau`$, where $`\ell`$ is the `extended_witness_length` parameter
    /// passed to [`RandomVoleP::create()`];
    /// $`r`$ is the [`VoleSizeParam`](crate::parameters::VoleSizeParam); and $`\tau`$ is the [`RepetitionParam`].
    fn count(&self) -> usize;

    /// Get the number of extended witness elements supported by this random VOLE instance.
    fn extended_witness_length(&self) -> usize;

    /// Get the mask for the witness; this is $`\bf u_{[1..\ell]}`$ in the paper, where
    /// $`\ell`$ is the value returned by [`RandomVoleP::extended_witness_length()`].
    ///
    /// In the paper, this is used in Figure 7, Round 1, step 1.
    ///
    /// Important: the values returned from this method must not overlap with those returned by
    /// [`RandomVoleP::aggregate_commitment_values()`].
    fn witness_mask(&self) -> &[F2];

    /// Gets the VOLE values ($`u_i \text{ for } i \in [\ell + 1..\ell + r\tau]`$ in the paper),
    /// embedded into [`FLambda`] from [`F2`].
    ///
    /// In the paper, this is defined in Figure 7, Round 1, step 2 and used in Round 3, step 2.
    /// These are combined into a mask for the aggregated commitment $`\tilde a`$.
    ///
    /// Important: the values returned from this method must not overlap with those returned by
    /// [`RandomVoleP::witness_mask()`].
    fn aggregate_commitment_values(&self)
    -> Array<FLambda<Self::Params>, MaskLength<Self::Params>>;

    /// Gets the VOLE masks ($`v_i \text{ for } i \in [\ell + 1..\ell + r\tau]`$ in the paper),
    /// lifted into [`FLambda`] from `[`[`F8b`]`; `SecurityParam`]`.
    ///
    /// In the paper, this is defined in Figure 7, Round 1, step 2 and used in Round 3, step 2.
    /// These are combined into a mask for the aggregated commitment $`\tilde b`$.
    ///
    /// Important: the values returned from this method must not overlap with those returned by
    /// [`RandomVoleP::witness_mask()`].
    fn aggregate_commitment_masks(&self) -> Array<FLambda<Self::Params>, MaskLength<Self::Params>>;

    /// Get the `i`th component of the VOLE mask (`v` in the paper), lifted into [`FLambda`] from
    /// a [$`\tau`$](crate::parameters::RepetitionParam)-length vector in [`F8b`].
    ///
    /// In the paper, this is defined in Figure 7, Round 1, step 3 and used in Round 3, steps 1
    /// and 2.
    ///
    /// The index `i` must be in the range $`[0, \ell)`$, where $`\ell`$ is the
    /// value returned by [`RandomVoleP::extended_witness_length()`].
    fn vole_mask(&self, i: usize) -> Result<FLambda<Self::Params>>;

    /// Compute a partial decommitment to this set of random VOLEs.
    ///
    /// This method simulates the verifier revealing their choice bits and receiving the
    /// decommitments to the VOLEs. As mentioned above, this must consume the VOLEs because
    /// it would be insecure for the prover to make any further computations based on the random
    /// VOLEs after the verifier "reveals" their choice bits.
    ///
    /// In the paper, this is implicit in Figure 7, Verification, step 1. However, the paper is
    /// written interactively; in this implementation, this will be called by the prover and the
    /// output incorporated into the proof.
    ///
    /// The challenge must incorporate all public information, including the degree 0 and 1
    /// commitments and all previous challenges.
    fn decommit(
        self,
        decom_challenge: &Array<u8, SecurityParamBytes<Self::Params>>,
    ) -> Self::Decommitment;
}

/// Methods for a verifier to reconstruct / verify and use an instance of VOLE.
pub trait RandomVoleV {
    /// The protocol parameters this VOLE is instantiated at.
    type Params: Params;

    /// Decommitment information for the random VOLE.
    ///
    /// This must only contain information that is safe to be sent to the verifier at the end of
    /// the protocol.
    type Decommitment;

    /// Reconstruct the VOLE material from a decommitment in a proof.
    ///
    /// In the ideal functionality, this corresponds to the `get` function.
    /// In practice, this "expands" the decommitment information, performs
    /// any checks, corrections, challenge evaluations, and any other details
    /// that need to happen before the VOLE key ∆ and the VOLE value tags `Q`
    /// are computed.
    fn reconstruct(
        decom: &Self::Decommitment,
        chall3: &Chall3<Self::Params>,
        transcript: &mut Transcript,
    ) -> Self;

    /// Get the length of the extended witness.
    fn extended_witness_length(&self) -> usize;

    /// Get the verifier key array $`\mathbf \Delta`$.
    fn verifier_key_array(&self) -> &Array<F8b, RepetitionParam<Self::Params>>;

    /// Get the lifted verifier key $`\Delta`$.
    fn verifier_key(&self) -> FLambda<Self::Params>;

    /// Get the value tags corresponding to the witness $`\mathbf Q_{[0..\ell)}`$,
    /// where $`\ell`$ is the [`Self::extended_witness_length`].
    fn witness_voles(&self) -> &[Array<F8b, RepetitionParam<Self::Params>>];

    /// Get the value tags corresponding to the mask
    /// $`\mathbf Q_{[\ell..\ell + \lambda)}`$, where $`\ell`$ is the
    /// [`Self::extended_witness_length`] and $`\lambda`$ is the security
    /// parameter (and equal to [`RepetitionParam`]` * `[`VoleSizeParam`](crate::parameters::VoleSizeParam)).
    fn mask_voles(&self) -> Array<FLambda<Self::Params>, MaskLength<Self::Params>>;
}
