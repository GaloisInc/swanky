use std::iter::repeat_with;

use mac_n_cheese_sieve_parser::WireId;
use swanky_field::FiniteRing;
use swanky_field_binary::{F128b, F2};
use swanky_serialization::CanonicalSerialize;

use crate::parameters::{FIELD_SIZE, REPETITION_PARAM, SECURITY_PARAM, VOLE_SIZE_PARAM};

pub(crate) struct Transcript<'a>(&'a mut merlin::Transcript);

impl<'a> From<&'a mut merlin::Transcript> for Transcript<'a> {
    fn from(transcript: &'a mut merlin::Transcript) -> Self {
        Self(transcript)
    }
}

impl<'a> AsMut<merlin::Transcript> for Transcript<'a> {
    fn as_mut(&mut self) -> &mut merlin::Transcript {
        self.0
    }
}

impl<'a> Transcript<'a> {
    /// Put all the known public values into the transcript!
    ///
    /// This doesn't incorporate any representation of the circuit itself.
    pub(crate) fn append_public_values(&mut self) {
        self.0
            .append_message(b"lambda: security parameter", &SECURITY_PARAM.to_le_bytes());
        self.0
            .append_message(b"p: field size", &FIELD_SIZE.to_le_bytes());
        self.0
            .append_message(b"r: VOLE size parameter", &VOLE_SIZE_PARAM.to_le_bytes());
        self.0.append_message(
            b"tau: repetition parameter",
            &REPETITION_PARAM.to_le_bytes(),
        );
    }

    /// Adds a public input from the public input stream to the transcript.
    ///
    /// At time of defining, we don't actually support public inputs. If we do add support, we
    /// should call this method for every public input as we traverse the circuit.
    /// This may require a new preprocessing pass for the verifier, in order to incorporate these
    /// before the initial witness commitment is generated.
    #[allow(unused)]
    pub(crate) fn append_public_input(&mut self, wid: WireId, public_input: &F2) {
        self.0
            .append_message(b"public input on wire id: wid", &wid.to_le_bytes());
        self.0
            .append_message(b"public input on wire id: value", &public_input.to_bytes());
    }

    /// Adds the commitment to the witness to the transcript.
    pub(crate) fn append_witness_commitment(&mut self, witness_commitment: &[F2]) {
        let bytes = witness_commitment
            .iter()
            .flat_map(|f2| f2.to_bytes())
            .collect::<Vec<_>>();
        self.0
            .append_message(b"d: commitment to witness", bytes.as_slice());
    }

    /// Extracts a challenge for each polynomial from the transcript.
    ///
    /// TODO #259: Consider simplifying this into a single seed drawn from the transcript and fed
    /// into a PRG.
    pub(crate) fn extract_witness_challenges(&mut self, polynomial_count: usize) -> Vec<F128b> {
        repeat_with(|| {
            let mut bytes = [0u8; 16];
            self.0
                .challenge_bytes(b"chi_i: witness challenge", &mut bytes);
            F128b::from_uniform_bytes(&bytes)
        })
        .take(polynomial_count)
        .collect()
    }

    /// Adds the commitment to the aggregated polynomial coefficients to the transcript.
    pub(crate) fn append_polynomial_commitments(
        &mut self,
        degree_0_commitment: &F128b,
        degree_1_commitment: &F128b,
    ) {
        self.0
            .append_message(b"b~: degree 0 commitment", &degree_0_commitment.to_bytes());
        self.0
            .append_message(b"a~: degree 1 commitment", &degree_1_commitment.to_bytes());
    }

    pub(crate) fn get_challenge_vc(&mut self, dest: &mut [u8]) {
        self.0.challenge_bytes(b"challene to open vc", dest);
    }
}
