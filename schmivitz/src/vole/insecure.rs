//! Instantiates an insecure version of VOLE for use in development.
//!
//!
//! ⚠️ This should be removed once there is a secure version of VOLE!
//!

use std::iter::{repeat_with, zip};

use crate::parameters::{REPETITION_PARAM, VOLE_SIZE_PARAM};
use eyre::{bail, eyre, Result};
use rand::{CryptoRng, RngCore};
use swanky_field::{FiniteRing, IsSubFieldOf};
use swanky_field_binary::{F128b, F8b, F2};

use super::RandomVole;

struct InsecureVole {
    /// Number of VOLEs requested.
    extended_witness_length: usize,

    /// Random values $`\bf u`$ that were committed to.
    ///
    /// Guarantee: This is length `extended_witness_length`.
    values: Vec<F2>,

    /// Verifier's chosen random key $`\bf \Delta`$.
    #[allow(unused)]
    verifier_key: [F8b; REPETITION_PARAM],

    /// Masks for the random values $`\bf V`$.
    ///
    /// Guarantee: This has length `extended_witness_length` $`+ r\tau `$, where $`r`$ is the
    /// [`VOLE_SIZE_PARAM`] and $`\tau`$ is the [`REPETITION_PARAM`].
    masks: Vec<[F8b; REPETITION_PARAM]>,
}
impl RandomVole for InsecureVole {
    type Decommitment = InsecureCommitments;

    fn create(
        extended_witness_length: usize,
        transcript: &mut merlin::Transcript,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Self {
        // In a secure version of VOLE, we would populate the transcript with more useful
        // or relevant context about the VOLE instantiation.
        transcript.append_message(
            b"VOLE type",
            format!(
                "Creating {} totally local & insecure VOLEs!!",
                extended_witness_length
            )
            .as_bytes(),
        );

        // Choose random values for everything.
        // NB: This will fail on a 32-bit target if the witness length is > 2^32
        let values = repeat_with(|| F2::random(rng))
            .take(extended_witness_length)
            .collect();

        // This unwrap is safe because we hardcoded the length
        let verifier_key = repeat_with(|| F8b::random(rng))
            .take(REPETITION_PARAM)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // This unwrap is safe because we hardcoded the length
        let masks = repeat_with(|| {
            repeat_with(|| F8b::random(rng))
                .take(REPETITION_PARAM)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        })
        .take(extended_witness_length + REPETITION_PARAM * VOLE_SIZE_PARAM)
        .collect();

        Self {
            extended_witness_length,
            values,
            verifier_key,
            masks,
        }
    }

    fn count(&self) -> usize {
        self.extended_witness_length + REPETITION_PARAM * VOLE_SIZE_PARAM
    }

    fn witness_mask(&self) -> &[F2] {
        &self.values[0..self.extended_witness_length]
    }

    fn commitment_mask(&self, i: u8) -> Result<F128b> {
        if i < 1 || i as usize > REPETITION_PARAM * VOLE_SIZE_PARAM {
            bail!(
                "commitment mask index out of range: should be in [1, 128], but got {}",
                i
            );
        }
        // The paper one-indexes stuff; subtract 1 to make it a zero-index.
        Ok(self.values[self.extended_witness_length + i as usize - 1].into())
    }

    fn vole_mask(&self, i: usize) -> Result<F128b> {
        if i < 1 || i > self.count() {
            bail!(
                "vole mask index out of range: should be in [1, {}], but got {}",
                self.count(),
                i
            );
        }
        // Adjust for one-indexing; bail if messed up the mask length.
        let unlifted: &[F8b; REPETITION_PARAM] =
            self.masks[i - 1].as_slice().try_into().map_err(|_| {
                eyre!("Internal error: expected mask entry to be exactly length 16, but it wasn't")
            })?;

        Ok(F8b::form_superfield(unlifted.into()))
    }

    fn decommit(self, _transcript: &mut merlin::Transcript) -> Self::Decommitment {
        // NB: in a real protocol, we would decommit based on a challenge pulled from the
        // transcript. This is fully insecure, so there's no validation that the verifier
        // could actually do.

        // Compute uΔ^T (where Δ^T is the transpose of the verifier key)
        let u_delta = self
            .values
            .iter()
            .map(|ui| self.verifier_key.map(|delta| *ui * delta))
            .collect::<Vec<_>>();

        assert_eq!(u_delta.len(), self.extended_witness_length);

        // Add V + uΔ^T
        let verifier_commitments = zip(self.masks, u_delta)
            .map(|(v, ud)| {
                zip(v, ud)
                    .map(|(v, ud)| v + ud)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect();

        Self::Decommitment {
            extended_witness_length: self.extended_witness_length,
            verifier_key: self.verifier_key,
            verifier_commitments,
        }
    }
}

#[allow(unused)]
struct InsecureCommitments {
    /// Number of VOLEs requested.
    extended_witness_length: usize,

    /// Verifier's chosen random key $`\bf \Delta`$.
    verifier_key: [F8b; REPETITION_PARAM],

    /// Commitments $`\bf Q`$ to the random values using the specified key and masks.
    ///
    /// Guarantee: This has length `extended_witness_length` $`+ r\tau `$, where $`r`$ is the
    /// [`VOLE_SIZE_PARAM`] and $`\tau`$ is the [`REPETITION_PARAM`].
    verifier_commitments: Vec<[F8b; REPETITION_PARAM]>,
}

#[allow(unused)]
impl InsecureCommitments {
    /// Get the length of the extended witness (e.g. the number of VOLEs requested).
    pub(crate) fn extended_witness_length(&self) -> usize {
        self.extended_witness_length
    }

    /// Get the lifted verifier key ($`\Delta`$ in the paper).
    pub(crate) fn verifier_key(&self) -> F128b {
        F8b::form_superfield(&self.verifier_key.into())
    }

    /// Get the VOLEs corresponding to the witness ($`\bf Q_{[1..\ell]}`$ in the paper).
    ///
    /// The output is guaranteed to be [`Self::extended_witness_length()`].
    pub(crate) fn witness_voles(&self) -> &[[F8b; REPETITION_PARAM]] {
        &self.verifier_commitments[0..self.extended_witness_length]
    }

    /// Get the lifted VOLEs corresponding to the mask for the aggregate commitment
    /// ($`q_{\ell+1}, \dots, q_{\ell + r\tau}`$ in the paper).
    pub(crate) fn mask_voles(&self) -> [F128b; REPETITION_PARAM * VOLE_SIZE_PARAM] {
        // Lift the commitments -- we only want the last $`r\tau`$ of them, so we skip the first ones.
        // This will panic if we constructed the type with the wrong length.
        self.verifier_commitments
            .iter()
            .skip(self.extended_witness_length)
            .map(|q| -> F128b { F8b::form_superfield(q.into()) })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}
