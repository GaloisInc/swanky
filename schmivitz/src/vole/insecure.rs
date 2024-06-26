//! Instantiates an insecure version of VOLE for use in development.
//!
//!
//! ⚠️ This should be removed once there is a secure version of VOLE!
//!

use std::iter::{repeat_with, zip};

use crate::parameters::{REPETITION_PARAM, VOLE_SIZE_PARAM};
use eyre::{bail, Result};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use swanky_field::{FiniteRing, IsSubFieldOf};
use swanky_field_binary::{F128b, F8b, F2};

use super::RandomVole;

#[derive(Clone)]
pub(crate) struct InsecureVole {
    /// Number of VOLEs requested.
    extended_witness_length: usize,

    /// Random values $`\bf u`$ that were committed to.
    ///
    /// Guarantee: This has length `extended_witness_length` + r\tau `$, where $`r`$ is the
    /// [`VOLE_SIZE_PARAM`] and $`\tau`$ is the [`REPETITION_PARAM`].
    values: Vec<F2>,

    /// Verifier's chosen random key $`\bf \Delta`$.
    verifier_key: [F8b; REPETITION_PARAM],

    /// Masks for the random values $`\bf V`$.
    ///
    /// Guarantee: This has length `extended_witness_length` $`+ r\tau `$, where $`r`$ is the
    /// [`VOLE_SIZE_PARAM`] and $`\tau`$ is the [`REPETITION_PARAM`].
    masks: Vec<[F8b; REPETITION_PARAM]>,
}
impl RandomVole for InsecureVole {
    type Decommitment = InsecureCommitments;
    type VoleChallenge = [u8; 16];
    type VoleDecommitmentChallenge = [u8; 16];

    fn extract_vole_challenge(
        transcript: &mut Transcript,
        extended_witness_length: usize,
    ) -> Self::VoleChallenge {
        transcript.append_message(
            b"VOLE type",
            format!(
                "Creating {} totally local & insecure VOLEs!!",
                extended_witness_length
            )
            .as_bytes(),
        );
        let mut challenge = [0; 16];
        transcript.challenge_bytes(b"insecure VOLE creation challenge", &mut challenge);
        challenge
    }

    fn create(
        extended_witness_length: usize,
        transcript: &mut merlin::Transcript,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> (Self, Self::VoleChallenge) {
        // In a secure version of VOLE, we would populate the transcript with more useful
        // or relevant context about the VOLE instantiation.
        let challenge = Self::extract_vole_challenge(transcript, extended_witness_length);

        let total_vole_count = extended_witness_length + REPETITION_PARAM * VOLE_SIZE_PARAM;

        // Choose random values for everything.
        // NB: This will fail on a 32-bit target if the witness length is > 2^32
        let values = repeat_with(|| F2::random(rng))
            .take(total_vole_count)
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
        .take(total_vole_count)
        .collect();

        (
            Self {
                extended_witness_length,
                values,
                verifier_key,
                masks,
            },
            challenge,
        )
    }

    fn count(&self) -> usize {
        self.extended_witness_length + REPETITION_PARAM * VOLE_SIZE_PARAM
    }

    fn extended_witness_length(&self) -> usize {
        self.extended_witness_length
    }

    fn witness_mask(&self) -> &[F2] {
        &self.values[0..self.extended_witness_length]
    }

    fn aggregate_commitment_values(&self) -> [F128b; REPETITION_PARAM * VOLE_SIZE_PARAM] {
        self.values
            .iter()
            .skip(self.extended_witness_length)
            .map(|f2| F128b::from(*f2))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn aggregate_commitment_masks(&self) -> [F128b; REPETITION_PARAM * VOLE_SIZE_PARAM] {
        self.masks
            .iter()
            .skip(self.extended_witness_length)
            .map(|mask| F8b::form_superfield(mask.into()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn vole_mask(&self, i: usize) -> Result<F128b> {
        if i >= self.extended_witness_length() {
            bail!(
                "vole mask index out of range: should be in [0, {}), but got {}",
                self.extended_witness_length(),
                i
            );
        }
        Ok(F8b::form_superfield(&self.masks[i].into()))
    }

    fn extract_decommitment_challenge(
        transcript: &mut Transcript,
    ) -> Self::VoleDecommitmentChallenge {
        let mut challenge = [0; 16];
        transcript.challenge_bytes(b"insecure VOLE decommitment challenge", &mut challenge);
        challenge
    }

    fn decommit(
        self,
        transcript: &mut merlin::Transcript,
    ) -> (Self::Decommitment, Self::VoleDecommitmentChallenge) {
        // NB: in a real protocol, we would decommit based on a challenge pulled from the
        // transcript. In the insecure version, we don't actually use this challenge to
        // determine anything about the decommitment, but we still generate it for fun.
        let challenge = Self::extract_decommitment_challenge(transcript);

        // Compute uΔ^T (where Δ^T is the transpose of the verifier key)
        let u_delta = self
            .values
            .iter()
            .map(|ui| self.verifier_key.map(|delta| *ui * delta))
            .collect::<Vec<_>>();

        // Add V + uΔ^T
        // The unwrap is safe because both internal types are known to be length 16
        let verifier_commitments = zip(self.masks, u_delta)
            .map(|(vs, uds)| {
                zip(vs, uds)
                    .map(|(v, ud)| v + ud)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<_>>();

        (
            Self::Decommitment {
                extended_witness_length: self.extended_witness_length,
                verifier_key: self.verifier_key,
                verifier_commitments,
            },
            challenge,
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) struct InsecureCommitments {
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
    /// Validate that the partial decommitment is correctly formed with respect to itself.
    pub(crate) fn validate_commitments(&self) -> Result<()> {
        let expected_num_commitments =
            self.extended_witness_length + REPETITION_PARAM * VOLE_SIZE_PARAM;
        if self.verifier_commitments.len() != expected_num_commitments {
            bail!(
                "Invalid insecure partial vole decommit: expected {} commitments, got {}",
                expected_num_commitments,
                self.verifier_commitments.len()
            )
        }

        Ok(())
    }

    /// Get the length of the extended witness (e.g. the number of VOLEs requested).
    pub(crate) fn extended_witness_length(&self) -> usize {
        self.extended_witness_length
    }

    /// Get verifier key ($`\bf\Delta`$ in the paper).
    pub(crate) fn verifier_key_array(&self) -> &[F8b; REPETITION_PARAM] {
        &self.verifier_key
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

#[cfg(test)]
mod tests {
    use merlin::Transcript;
    use rand::thread_rng;

    use crate::{
        parameters::{REPETITION_PARAM, VOLE_SIZE_PARAM},
        vole::{insecure::InsecureVole, RandomVole},
    };

    #[test]
    fn everything_is_the_expected_size() {
        let rng = &mut thread_rng();
        let transcript = &mut Transcript::new(b"testing");

        let witness = 100;
        let (voles, _challenge) = InsecureVole::create(witness, transcript, rng);

        assert_eq!(voles.count(), witness + REPETITION_PARAM * VOLE_SIZE_PARAM);
        assert_eq!(voles.witness_mask().len(), witness);
        // These will panic if there's a length problem:
        voles.aggregate_commitment_masks();
        voles.aggregate_commitment_values();

        for i in 0..voles.count() {
            if i < witness {
                assert!(voles.vole_mask(i).is_ok());
            } else {
                assert!(voles.vole_mask(i).is_err());
            }
        }

        let (decom, _challenge) = voles.decommit(transcript);

        assert_eq!(decom.extended_witness_length(), witness);
        assert_eq!(decom.witness_voles().len(), witness);
        // This will panic if there's a length problem:
        decom.mask_voles();
    }
}
