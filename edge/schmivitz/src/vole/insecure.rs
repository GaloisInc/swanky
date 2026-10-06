//! Instantiates an insecure version of VOLE for use in development.
//!
//!
//! ⚠️ This should be removed once there is a secure version of VOLE!
//!

use std::iter::{repeat_with, zip};

use crate::parameters::{FLambda, Params, RepetitionParam};
use crate::vole::{MaskLength, SecurityParamBytes};
use hybrid_array::Array;
use hybrid_array::typenum::Unsigned;

use merlin::Transcript;
use rand::CryptoRng;
use swanky_error::{ErrorKind, Result, bail};
use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F8b};

use super::{AsSecretBytes, Chall3, DecommitmentSerde, RandomVoleP, RandomVoleV, lift};

#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct InsecureVole<P: Params> {
    /// Number of VOLEs requested.
    extended_witness_length: usize,

    /// Random values $`\bf u`$ that were committed to.
    ///
    /// Guarantee: This has length `extended_witness_length` + r\tau `$, where $`r`$ is the
    /// [`VoleSizeParam`] and $`\tau`$ is the [`RepetitionParam`].
    values: Vec<F2>,

    /// Verifier's chosen random key $`\bf \Delta`$.
    verifier_key: Array<F8b, RepetitionParam<P>>,

    /// Masks for the random values $`\bf V`$.
    ///
    /// Guarantee: This has length `extended_witness_length` $`+ r\tau `$, where $`r`$ is the
    /// [`VoleSizeParam`] and $`\tau`$ is the [`RepetitionParam`].
    masks: Vec<Array<F8b, RepetitionParam<P>>>,
}

/// Updates transcript with public material available at VOLE creation and VOLE reconstruction
/// and extracts a challenge.
fn update_transcript(transcript: &mut Transcript, extended_witness_length: usize) -> [u8; 16] {
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

impl<P: Params> RandomVoleP for InsecureVole<P> {
    type Params = P;
    type Decommitment = InsecureCommitments<P>;
    type VoleChallenge = [u8; 16];

    fn create<Secret: AsSecretBytes>(
        extended_witness_length: usize,
        transcript: &mut merlin::Transcript,
        _secret: &Secret,
        rng: &mut impl CryptoRng,
    ) -> (Self, Self::VoleChallenge) {
        // In a secure version of VOLE, we would populate the transcript with more useful
        // or relevant context about the VOLE instantiation.
        let challenge = update_transcript(transcript, extended_witness_length);

        let total_vole_count = extended_witness_length + MaskLength::<P>::USIZE;

        // Choose random values for everything.
        // NB: This will fail on a 32-bit target if the witness length is > 2^32
        let values = repeat_with(|| F2::random(rng))
            .take(total_vole_count)
            .collect();

        // This unwrap is safe because we hardcoded the length
        let verifier_key = repeat_with(|| F8b::random(rng))
            .take(RepetitionParam::<P>::USIZE)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // This unwrap is safe because we hardcoded the length
        let masks = repeat_with(|| {
            repeat_with(|| F8b::random(rng))
                .take(RepetitionParam::<P>::USIZE)
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
        self.extended_witness_length + MaskLength::<P>::USIZE
    }

    fn extended_witness_length(&self) -> usize {
        self.extended_witness_length
    }

    fn witness_mask(&self) -> &[F2] {
        &self.values[0..self.extended_witness_length]
    }

    fn aggregate_commitment_values(&self) -> Array<FLambda<P>, MaskLength<P>> {
        self.values
            .iter()
            .skip(self.extended_witness_length)
            .map(|f2| P::f2_embed(*f2))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn aggregate_commitment_masks(&self) -> Array<FLambda<P>, MaskLength<P>> {
        self.masks
            .iter()
            .skip(self.extended_witness_length)
            .map(lift::<P>)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn vole_mask(&self, i: usize) -> Result<FLambda<P>> {
        if i >= self.extended_witness_length() {
            bail!(
                ErrorKind::OtherError,
                "vole mask index out of range: should be in [0, {}), but got {}",
                self.extended_witness_length(),
                i
            );
        }
        Ok(lift::<P>(&self.masks[i]))
    }

    fn decommit(self, _challenge: &Array<u8, SecurityParamBytes<P>>) -> Self::Decommitment {
        // Compute uΔ^T (where Δ^T is the transpose of the verifier key)
        let u_delta = self
            .values
            .iter()
            .map(|ui| self.verifier_key.clone().map(|delta| *ui * delta))
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

        Self::Decommitment {
            extended_witness_length: self.extended_witness_length,
            verifier_key: self.verifier_key,
            verifier_commitments,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct InsecureCommitments<P: Params> {
    /// Number of VOLEs requested.
    extended_witness_length: usize,

    /// Verifier's chosen random key $`\bf \Delta`$.
    verifier_key: Array<F8b, RepetitionParam<P>>,

    /// Commitments $`\bf Q`$ to the random values using the specified key and masks.
    ///
    /// Guarantee: This has length `extended_witness_length` $`+ r\tau `$, where $`r`$ is the
    /// [`VoleSizeParam`] and $`\tau`$ is the [`RepetitionParam`].
    verifier_commitments: Vec<Array<F8b, RepetitionParam<P>>>,
}

impl<P: Params> InsecureCommitments<P> {
    /// Validate that the partial decommitment is correctly formed with respect to itself.
    /// TODO: put this inline somewhere -- maybe in `reconstruct`.
    #[allow(unused)]
    pub(crate) fn validate_commitments(&self) -> Result<()> {
        let expected_num_commitments = self.extended_witness_length + MaskLength::<P>::USIZE;
        if self.verifier_commitments.len() != expected_num_commitments {
            bail!(
                ErrorKind::OtherError,
                "Invalid insecure partial vole decommit: expected {} commitments, got {}",
                expected_num_commitments,
                self.verifier_commitments.len()
            )
        }

        Ok(())
    }
}

impl<P: Params> DecommitmentSerde for InsecureCommitments<P> {
    fn proof_size_estimate(&self) -> usize {
        unimplemented!()
    }
}

impl<P: Params> RandomVoleV for InsecureCommitments<P> {
    type Params = P;
    type Decommitment = InsecureCommitments<P>;

    fn reconstruct(
        decom: &Self::Decommitment,
        _chall3: &Chall3<P>,
        transcript: &mut Transcript,
    ) -> Self {
        // The output of this function is ignored since, in this insecure implementation,
        // it is not used for anything.
        update_transcript(transcript, decom.extended_witness_length);
        decom.clone()
    }

    /// Get the length of the extended witness (e.g. the number of VOLEs requested).
    fn extended_witness_length(&self) -> usize {
        self.extended_witness_length
    }

    /// Get verifier key ($`\bf\Delta`$ in the paper).
    fn verifier_key_array(&self) -> &Array<F8b, RepetitionParam<P>> {
        &self.verifier_key
    }

    /// Get the lifted verifier key ($`\Delta`$ in the paper).
    fn verifier_key(&self) -> FLambda<P> {
        lift::<P>(&self.verifier_key)
    }

    /// Get the VOLEs corresponding to the witness ($`\bf Q_{[1..\ell]}`$ in the paper).
    ///
    /// The output is guaranteed to be [`Self::extended_witness_length()`].
    fn witness_voles(&self) -> &[Array<F8b, RepetitionParam<P>>] {
        &self.verifier_commitments[0..self.extended_witness_length]
    }

    /// Get the lifted VOLEs corresponding to the mask for the aggregate commitment
    /// ($`q_{\ell+1}, \dots, q_{\ell + r\tau}`$ in the paper).
    fn mask_voles(&self) -> Array<FLambda<P>, MaskLength<P>> {
        // Lift the commitments -- we only want the last $`r\tau`$ of them, so we skip the first ones.
        // This will panic if we constructed the type with the wrong length.
        self.verifier_commitments
            .iter()
            .skip(self.extended_witness_length)
            .map(lift::<P>)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::parameters::{Binary128Bit, Binary256Bit};

    macro_rules! make_tests {
        (mod $name:ident { params = $params:ty $(,)? }) => {
            mod $name {
                use super::*;

                #[allow(dead_code)]
                type P = $params;

                use merlin::Transcript;
                use rand::rng;
                use swanky_field_binary::F2;

                use crate::vole::{MaskLength, RandomVoleP, RandomVoleV, insecure::InsecureVole};
                use hybrid_array::Array;
                use hybrid_array::typenum::Unsigned;

                #[test]
                fn everything_is_the_expected_size() {
                    let rng = &mut rng();
                    let transcript = &mut Transcript::new(b"testing");
                    let secret: Vec<F2> = Vec::new();

                    let witness = 100;
                    let (voles, _challenge) =
                        InsecureVole::<P>::create(witness, transcript, &secret, rng);

                    assert_eq!(voles.count(), witness + MaskLength::<P>::USIZE);
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

                    // Note: the challenge passed here is invalid because it's not drawn from transcript.
                    let decom = voles.decommit(&Array::default());

                    assert_eq!(decom.extended_witness_length(), witness);
                    assert_eq!(decom.witness_voles().len(), witness);
                    // This will panic if there's a length problem:
                    decom.mask_voles();
                }
            }
        };
    }

    make_tests! { mod binary_128_bit { params = Binary128Bit } }
    make_tests! { mod binary_256_bit { params = Binary256Bit } }
}
