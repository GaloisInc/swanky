//! Defines the overarching trait for VOLE and includes various implementations.
//!
//! Expected implementations:
//! - Dummy insecure version for non-blocking development
//! - Secure version as described in FAEST spec and paper
//!

pub(crate) mod insecure;

use eyre::Result;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use swanky_field_binary::{F128b, F2};

use crate::parameters::{REPETITION_PARAM, VOLE_SIZE_PARAM};

/// This defines the behavior needed to create and use non-interactive random VOLEs.
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
pub trait RandomVole
where
    Self: Sized,
{
    /// Decommitment information for the random VOLE.
    ///
    /// This must only contain information that is safe to be sent to the verifier at the end of
    /// the protocol.
    type Decommitment;

    /// Type of the challenge generated when creating the VOLEs.
    type VoleChallenge;

    /// Type of the challenge generated when decommitting the VOLEs.
    type VoleDecommitmentChallenge;

    /// Create a set of random VOLEs.
    ///
    /// This is particular to the protocol by Baum et al., so the total number of VOLEs created
    /// should be $`\ell + r\tau`$, where $`\ell`$ is the `extended_witness_length`;
    /// $`r`$ is the [`VOLE_SIZE_PARAM`]; and $`\tau`$ is the [`REPETITION_PARAM`].
    ///
    /// The [`Transcript`] passed here must already incorporate all public information known to
    /// both parties at the beginning of the proof, including
    /// the public [`parameters`](crate::parameters);
    /// some representation of the circuit being proven;
    /// any public inputs to the circuit; and
    /// any external context provided at the application level.
    /// Internally, it must incorporate any additional public parameters defined by this
    /// instantiation of `RandomVole` before generating the [`RandomVole::VoleChallenge`].
    fn create(
        extended_witness_length: usize,
        transcript: &mut Transcript,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> (Self, Self::VoleChallenge);

    /// Update the transcript with the extended witness length, plus any additional public
    /// parameters or public information known at time of creation, and generate the challenge
    /// used to create the random VOLE instances.
    ///
    /// It's implemented as a separate method so that a verifier can independently update the
    /// transcript without creating any VOLEs. A reasonable implementation would also call this
    /// method directly in the [`RandomVole::create()`] method.
    fn extract_vole_challenge(
        transcript: &mut Transcript,
        extended_witness_length: usize,
    ) -> Self::VoleChallenge;

    /// Get the total number of VOLE correlations supported by this random VOLE instance.
    ///
    /// This should be $`\ell + r\tau`$, where $`\ell`$ is the `extended_witness_length` parameter
    /// passed to [`RandomVole::create()`];
    /// $`r`$ is the [`VOLE_SIZE_PARAM`]; and $`\tau`$ is the [`REPETITION_PARAM`].
    fn count(&self) -> usize;

    /// Get the number of extended witness elements supported by this random VOLE instance.
    fn extended_witness_length(&self) -> usize;

    /// Get the mask for the witness; this is $`\bf u_{[1..\ell]}`$ in the paper, where
    /// $`\ell`$ is the value returned by [`RandomVole::extended_witness_length()`].
    ///
    /// In the paper, this is used in Figure 7, Round 1, step 1.
    ///
    /// Important: the values returned from this method must not overlap with those returned by
    /// [`RandomVole::aggregate_commitment_values()`].
    fn witness_mask(&self) -> &[F2];

    /// Gets the VOLE values ($`u_i \text{ for } i \in [\ell + 1..\ell + r\tau]`$ in the paper),
    /// embedded into [`F128b`] from [`F2`].
    ///
    /// In the paper, this is defined in Figure 7, Round 1, step 2 and used in Round 3, step 2.
    /// These are combined into a mask for the aggregated commitment $`\tilde a`$.
    ///
    /// Important: the values returned from this method must not overlap with those returned by
    /// [`RandomVole::witness_mask()`].
    fn aggregate_commitment_values(&self) -> [F128b; REPETITION_PARAM * VOLE_SIZE_PARAM];

    /// Gets the VOLE masks ($`v_i \text{ for } i \in [\ell + 1..\ell + r\tau]`$ in the paper),
    /// lifted into [`F128b`] from `[`[F8b](swanky_field_binary::F8b)`; 16]`.
    ///
    /// In the paper, this is defined in Figure 7, Round 1, step 2 and used in Round 3, step 2.
    /// These are combined into a mask for the aggregated commitment $`\tilde b`$.
    ///
    /// Important: the values returned from this method must not overlap with those returned by
    /// [`RandomVole::witness_mask()`].
    fn aggregate_commitment_masks(&self) -> [F128b; REPETITION_PARAM * VOLE_SIZE_PARAM];

    /// Get the `i`th component of the VOLE mask (`v` in the paper), lifted into [`F128b`] from
    /// a [$`\tau`$](crate::parameters::REPETITION_PARAM)-length vector in [`F8b`](swanky_field_binary::F8b).
    ///
    /// In the paper, this is defined in Figure 7, Round 1, step 3 and used in Round 3, steps 1
    /// and 2.
    ///
    /// The index `i` must be in the range $`[0, \ell)`$, where $`\ell`$ is the
    /// value returned by [`RandomVole::extended_witness_length()`].
    fn vole_mask(&self, i: usize) -> Result<F128b>;

    /// This method extracts a challenge used to decommit to the VOLEs.
    ///
    /// It's implemented as a separate method so that a verifier can independently derive the
    /// challenge without acutally calling the `decommit()` method (which is the responsibility of
    /// the prover). A reasonable implementation would also call this
    /// method directly in the [`RandomVole::decommit()`] method.
    fn extract_decommitment_challenge(
        transcript: &mut Transcript,
    ) -> Self::VoleDecommitmentChallenge;

    /// Compute a partial decommitment to this set of random VOLEs.
    ///
    /// This method simulates the verifier revealing their choice bits and receiving the
    /// decommitments to the VOLEs. As mentioned above, this must consume the VOLEs because
    /// it would be insecure for the prover to make any further computations based on the random
    /// VOLEs after the verifier "reveals" their choice bits. The "verifier's choice" is simulated
    /// via the [`RandomVole::VoleDecommitmentChallenge`] type, which must also be returned from
    /// this function so it can be encoded into the proof.
    ///
    /// In the paper, this is implicit in Figure 7, Verification, step 1. However, the paper is
    /// written interactively; in this implementation, this will be called by the prover and the
    /// output incorporated into the proof.
    ///
    /// The [`Transcript`] passed to this method must incorporate all public information contained
    /// in the proof, including the commitment to the de-randomized VOLEs ($`\tilde a`$ and
    /// $`\tilde b`$ in the paper).
    fn decommit(
        self,
        transcript: &mut Transcript,
    ) -> (Self::Decommitment, Self::VoleDecommitmentChallenge);
}
