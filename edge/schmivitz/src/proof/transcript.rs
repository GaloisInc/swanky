use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F128b};
use swanky_serialization::CanonicalSerialize;
use swanky_sieve_ir_parser::WireId;

use crate::parameters::{FIELD_SIZE, REPETITION_PARAM, SECURITY_PARAM, VOLE_SIZE_PARAM};

pub(crate) struct Transcript<'a>(&'a mut merlin::Transcript);

impl<'a> From<&'a mut merlin::Transcript> for Transcript<'a> {
    fn from(transcript: &'a mut merlin::Transcript) -> Self {
        Self(transcript)
    }
}

impl AsMut<merlin::Transcript> for Transcript<'_> {
    fn as_mut(&mut self) -> &mut merlin::Transcript {
        self.0
    }
}

impl Transcript<'_> {
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

    /// Extracts a challenge for each polynomial and assert zero from the transcript.
    ///
    /// Use the transcript to extract a seed challenge and use exponentiation to
    /// derive a vector of random values.
    pub(crate) fn extract_challenge(&mut self) -> ChiGenerator {
        let mut bytes = [0u8; 16];
        self.0
            .challenge_bytes(b"chi_i: witness challenge", &mut bytes);
        let seed = F128b::from_uniform_bytes(&bytes);
        ChiGenerator::new(seed)
    }

    /// Adds the commitment to the aggregated polynomial coefficients to the transcript.
    pub(crate) fn append_polynomial_commitments(
        &mut self,
        degree_0_commitment: &F128b,
        degree_1_commitment: &F128b,
        assert_zero_commitment: &F128b,
    ) {
        self.0
            .append_message(b"b~: degree 0 commitment", &degree_0_commitment.to_bytes());
        self.0
            .append_message(b"a~: degree 1 commitment", &degree_1_commitment.to_bytes());
        self.0.append_message(
            b"assert_zero commitment",
            &assert_zero_commitment.to_bytes(),
        );
    }

    pub(crate) fn extract_decommitment_challenge(&mut self) -> [u8; SECURITY_PARAM / 8] {
        let mut challenge = [0u8; SECURITY_PARAM / 8];
        self.0
            .challenge_bytes(b"decommitment challenge", &mut challenge);
        challenge
    }
}

/// Iterator that generates powers of chi challenges.
pub(crate) struct ChiGenerator {
    chi: F128b,
    power_of_chi: F128b,
}

impl ChiGenerator {
    pub(crate) fn new(chi: F128b) -> ChiGenerator {
        ChiGenerator {
            chi,
            power_of_chi: F128b::ONE,
        }
    }

    pub(crate) fn next(&mut self) -> F128b {
        self.power_of_chi *= self.chi;
        self.power_of_chi
    }
}
