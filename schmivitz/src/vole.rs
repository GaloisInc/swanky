//! Defines the overarching trait for VOLE and includes various implementations.
//!
//! Expected implementations:
//! - Dummy insecure version for non-blocking development
//! - Secure version as described in FAEST spec and paper
//!

use eyre::Result;
use merlin::Transcript;
use swanky_field_binary::F2;

/// This should be $`GF(2^{r\tau}) = GF(2^{120})`$.
#[allow(unused)]
struct F120b;

/// This should be $`GF(2^r) = GF(2^10)`$.
#[allow(unused)]
struct F10b;

/// This defines the behavior needed to create and use non-interactive random VOLEs.
///
/// It's tailored to the specific use case of the VOLE-in-the-head paper[^vole], including
/// hardcoding some lengths and field sizes based on the [fixed parameters](crate::parameters)
/// and generally having an API that corresponds to the components and uses of
/// random VOLEs in Figure 7 of the paper, rather than the generic usage.
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
trait RandomVole
where
    Self: Sized,
{
    /// Decommitment information for the random VOLE.
    ///
    /// This must only contain information that is safe to be sent to the verifier at the end of
    /// the protocol.
    type Decommitment;

    /// Create a set of random VOLEs.
    ///
    /// This is particular to the protocol by Baum et al., so the total number of VOLEs created
    /// should be $`\ell + r\tau`$, where $`\ell`$ is the `extended_witness_length`;
    /// $`r`$ is the [`VOLE_SIZE_PARAM`](crate::parameters::VOLE_SIZE_PARAM); and
    /// $`\tau`$ is the [`REPETITION_PARAM`](crate::parameters::REPETITION_PARAM).
    ///
    /// The [`Transcript`] passed here must already incorporate all public information known to
    /// both parties at the beginning of the proof, including
    /// the public [`parameters`](crate::parameters);
    /// some representation of the circuit being proven;
    /// any public inputs to the circuit; and
    /// any external context provided at the application level.
    /// Internally, it must incorporate any additional public parameters defined by this
    /// instantiation of `RandomVole`.
    fn create(extended_witness_length: u64, transcript: &mut Transcript) -> Self;

    /// Get the total number of VOLE correlations supported by this random VOLE instance.
    ///
    /// This should be $`\ell + r\tau`$, where $`\ell`$ is the `extended_witness_length` parameter
    /// passed to [`RandomVole::create()`];
    /// $`r`$ is the [`VOLE_SIZE_PARAM`](crate::parameters::VOLE_SIZE_PARAM); and
    /// $`\tau`$ is the [`REPETITION_PARAM`](crate::parameters::REPETITION_PARAM).
    fn count(&self) -> u64;

    /// Get the mask for the witness; this is $`\bf u_{[1..\ell]}`$ in the paper, where
    /// $`\ell`$ is the `extended_witness_length` passed to [`RandomVole::create()`].
    ///
    /// In the paper, this is used in Figure 7, Round 1, step 1.
    ///
    /// Important: the values returned from this method must not overlap with those returned by
    /// [`RandomVole::commitment_mask()`].
    fn witness_mask(&self) -> &[F2];

    /// Gets the `i`th component of the random value (`u` in the paper), embedded into [`F120b`]
    /// from [`F2`].
    ///
    /// In the paper, this is defined in Figure 7, Round 1, step 2 and used in Round 3, step 2.
    ///
    /// The index `i` must be in the range $`[1, r\tau] = [1, 120]`$, where
    /// $`r`$ is the [`VOLE_SIZE_PARAM`](crate::parameters::VOLE_SIZE_PARAM) and
    /// $`\tau`$ is the [`REPETITION_PARAM`](crate::parameters::REPETITION_PARAM).
    ///
    /// Important: the values returned from this method must not overlap with those returned by
    /// [`RandomVole::witness_mask()`].
    fn commitment_mask(&self, i: u8) -> Result<F120b>;

    /// Get the `i`th component of the VOLE mask (`v` in the paper), lifted into [`F120b`] from
    /// a [$`\tau`$](crate::parameters::REPETITION_PARAM)-length vector in [`F10b`].
    ///
    /// In the paper, this is defined in Figure 7, Round 1, step 3 and used in Round 3, steps 1
    /// and 2.
    ///
    /// The index `i` must be in the range $`[1, \ell + r\tau]`$, where $`\ell + r\tau`$ is the
    /// value returned by [`RandomVole::count()`].
    fn vole_mask(&self, i: u64) -> Result<F120b>;

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
    /// The [`Transcript`] passed to this method must incorporate all public information contained
    /// in the proof, including the commitment to the de-randomized VOLEs ($`\tilde a`$ and
    /// $`\tilde b`$ in the paper).
    fn decommit(self, transcript: &mut Transcript) -> Self::Decommitment;
}
