use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use swanky_serialization::CanonicalSerialize;
use swanky_sieve_ir_parser::WireId;

use crate::parameters::{
    FLambda, FieldSize, Params, RepetitionParam, SecurityParam, SecurityParamBytes, SmallVoleSize,
};
use hybrid_array::Array;
use hybrid_array::typenum::Unsigned;

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
    pub(crate) fn append_public_values<P: Params>(&mut self) {
        self.0.append_message(
            b"lambda: security parameter",
            &SecurityParam::<P>::USIZE.to_le_bytes(),
        );
        self.0
            .append_message(b"p: field size", &FieldSize::USIZE.to_le_bytes());
        self.0.append_message(
            b"r: VOLE size parameter",
            &SmallVoleSize::USIZE.to_le_bytes(),
        );
        self.0.append_message(
            b"tau: repetition parameter",
            &RepetitionParam::<P>::USIZE.to_le_bytes(),
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
    pub(crate) fn extract_challenge<P: Params>(&mut self) -> ChiGenerator<P> {
        // NOTE: We use a 16 byte challenge here regardless of the security parameter. This is
        // because [`FiniteField::from_random_bytes`] always takes 16 bytes of entropy. In the
        // 256-bit case, this is internally passed through a PRNG to get a full field element.
        let mut bytes = [0u8; 16];
        self.0
            .challenge_bytes(b"chi_i: witness challenge", &mut bytes);
        let seed = FLambda::<P>::from_uniform_bytes(&bytes);
        ChiGenerator::new(seed)
    }

    /// Adds the commitment to the aggregated polynomial coefficients to the transcript.
    pub(crate) fn append_polynomial_commitments<P: Params>(
        &mut self,
        degree_0_commitment: &FLambda<P>,
        degree_1_commitment: &FLambda<P>,
        assert_zero_commitment: &FLambda<P>,
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

    pub(crate) fn extract_decommitment_challenge<P: Params>(
        &mut self,
    ) -> Array<u8, SecurityParamBytes<P>> {
        let mut challenge = Array::default();
        self.0
            .challenge_bytes(b"decommitment challenge", &mut challenge);
        challenge
    }
}

/// Iterator that generates powers of chi challenges.
pub(crate) struct ChiGenerator<P: Params> {
    chi: FLambda<P>,
    power_of_chi: FLambda<P>,
}

impl<P: Params> ChiGenerator<P> {
    pub(crate) fn new(chi: FLambda<P>) -> Self {
        ChiGenerator {
            chi,
            power_of_chi: FLambda::<P>::ONE,
        }
    }

    pub(crate) fn next(&mut self) -> FLambda<P> {
        self.power_of_chi *= self.chi;
        self.power_of_chi
    }
}
