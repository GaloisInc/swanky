//! Instantiates an insecure version of VOLE for use in development.
//!
//!
//! ⚠️ This should be removed once there is a secure version of VOLE!
//!

use std::iter::repeat_with;

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

struct InsecureCommitments;

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
        todo!()
    }
}
