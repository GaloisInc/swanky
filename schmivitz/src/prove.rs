use eyre::{bail, Result};
use mac_n_cheese_sieve_parser::{text_parser::RelationReader, Number, Type};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use std::{
    io::{Read, Seek},
    iter::{repeat_with, zip},
    path::Path,
};
use swanky_field::FiniteRing;
use swanky_field_binary::{F128b, F2};
use swanky_serialization::CanonicalSerialize;

use crate::{
    helpers::combine,
    parameters::FIELD_SIZE,
    prove::{prover_preparer::ProverPreparer, prover_traverser::ProverTraverser},
    vole::RandomVole,
};

mod prover_preparer;
mod prover_traverser;
mod verifier_traverser;

/// Zero-knowledge proof of knowledge of a circuit.
///
/// TODO #251: Add VOLE challenge and decommitment challenge to this type.
#[allow(unused)]
#[derive(Debug, Clone)]
pub struct Proof<Vole: RandomVole> {
    /// Commitment to the extended witness ($`d`$ in the paper).
    witness_commitment: Vec<F2>,
    /// Challenges generated after committing to the witness
    witness_challenges: Vec<F128b>,
    /// Aggregated commitment to the degree-0 term coefficients for each gate in the circuit
    /// ($`\tilde b`$ in the paper).
    degree_0_commitment: F128b,
    /// Aggregated commitment to the degree-1 term coefficients for each gate in the circuit
    /// ($`\tilde a`$ in the paper).
    degree_1_commitment: F128b,
    /// Partial decommitment of the VOLEs.
    partial_decommitment: Vole::Decommitment,
}

impl<Vole: RandomVole> Proof<Vole> {
    /// Create a proof of knowledge of a witness that satisfies the given circuit.
    pub fn prove<T, R>(
        circuit: &mut T,
        private_input: &Path,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Result<Self>
    where
        T: Read + Seek + Clone,
        R: CryptoRng + RngCore,
    {
        let reader = RelationReader::new(circuit.clone())?;
        Self::validate_circuit_header(&reader)?;

        // Evaluate the circuit in the clear to get the full witness and all wire values
        let mut prepared_circuit = ProverPreparer::new_from_path(private_input)?;
        reader.read(&mut prepared_circuit)?;
        let (witness, wire_values) = prepared_circuit.into_parts();
        let witness_len = witness.len();

        // TODO #251: Add public values to transcript here!!!
        transcript.append_message(b"commit to public values", b"todo: commit properly");

        // Get a set of random VOLEs, one for each value in the extended witness
        // TODO #251: This should return a challenge as well to put into the proof
        let voles = Vole::create(witness_len, transcript, rng);

        // Commit to extended witness (`d` in the paper)
        let witness_commitment = zip(witness, voles.witness_mask())
            .map(|(w, u)| w - u)
            .collect::<Vec<_>>();

        // TODO #251: Add witness commitment to transcript here!!!
        transcript.append_message(b"commit to witness", b"todo: commit the actual value");

        // Generate challenges
        let witness_challenges = repeat_with(|| {
            let mut bytes = [0u8; 16];
            transcript.challenge_bytes(b"challenge part 2", &mut bytes);
            F128b::from_uniform_bytes(&bytes)
        })
        .take(witness_len)
        .collect::<Vec<_>>();

        // Traverse circuit to compute the coefficients for the degree 0 and 1 terms for each
        // gate / polynomial (`A_i0` and `A_i1` in the paper) and start to aggregate these with
        // the challenges.
        let mut circuit_traverser = ProverTraverser::new(wire_values, witness_challenges, voles)?;
        RelationReader::new(circuit)?.read(&mut circuit_traverser)?;
        let (degree_0_aggregation, degree_1_aggregation, voles, witness_challenges) =
            circuit_traverser.into_parts();

        // Compute masks for the aggregated coefficients (`v*`, `u*` in the paper)
        let degree_0_mask = combine(voles.aggregate_commitment_masks());
        let degree_1_mask = combine(voles.aggregate_commitment_values());

        // Finish computing aggregated responses (`a~`, `b~` in the paper)
        let degree_0_commitment = degree_0_aggregation + degree_0_mask;
        let degree_1_commitment = degree_1_aggregation + degree_1_mask;

        // TODO #251: Add aggregated responses to transcript here!!!
        transcript.append_message(b"b~: degree 0 commitment", &degree_0_commitment.to_bytes());
        transcript.append_message(b"a~: degree 1 commitment", &degree_1_commitment.to_bytes());

        // Decommit the VOLEs
        // TODO #251: This should also return the challenge used to decommit, so we can put it
        // into the proof.
        let partial_decommitment = voles.decommit(transcript);

        // Form the proof
        Ok(Self {
            witness_commitment,
            witness_challenges,
            degree_0_commitment,
            degree_1_commitment,
            partial_decommitment,
        })
    }

    fn extended_witness_length(&self) -> usize {
        self.witness_commitment.len()
    }

    /// Verify the proof.
    pub fn verify(&self, transcript: &mut Transcript) -> Result<()> {
        // TODO #251: Add public values to transcript here!!!
        transcript.append_message(b"commit to public values", b"todo: commit properly");
        Vole::update_transcript(transcript, self.extended_witness_length());

        // TODO #251: Squeeze first VOLE challenge and check it against the value in the proof

        // TODO #251: Add witness commitment to transcript here!!!
        let _witness_commitment = self.witness_commitment.as_slice();
        transcript.append_message(b"commit to witness", b"todo: commit the actual value");

        // Generate challenges
        let expected_witness_challenges = repeat_with(|| {
            let mut bytes = [0u8; 16];
            transcript.challenge_bytes(b"challenge part 2", &mut bytes);
            F128b::from_uniform_bytes(&bytes)
        })
        .take(self.witness_challenges.len())
        .collect::<Vec<_>>();

        if expected_witness_challenges != self.witness_challenges {
            bail!("Verification failed: Witness challenges did not match expected values");
        }
        Ok(())
    }

    /// Validate that the circuit can be processed by the system, according to the header info.
    ///
    /// Note that the system can still fail to form proofs over circuits that pass this check, like
    /// if it includes an unsupported gate.
    ///
    /// Requirements:
    /// - Must not allow any plugins
    /// - Must not allow any conversions
    /// - Must not allow any types other than $`\mathbb F_2`$
    fn validate_circuit_header<T: Read + Seek>(circuit_reader: &RelationReader<T>) -> Result<()> {
        let header = circuit_reader.header();
        if !header.plugins.is_empty() {
            bail!("Invalid circuit: VOLE-in-the-head does not support any plugins")
        }

        if !header.conversion.is_empty() {
            bail!("Invalid circuit: VOLE-in-the-head does not support conversions")
        }

        let expected_modulus = Number::from(FIELD_SIZE as u64);
        match header.types[..] {
            [Type::Field { modulus }] if modulus == expected_modulus => {}
            _ => bail!("Invalid circuit: VOLE-in-the-head only supports elements in F_2"),
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Cursor};

    use eyre::Result;
    use mac_n_cheese_sieve_parser::text_parser::RelationReader;
    use merlin::Transcript;
    use rand::thread_rng;
    use std::io::Write;
    use tempfile::tempdir;

    use crate::vole::insecure::InsecureVole;

    use super::Proof;

    #[test]
    fn header_cannot_include_plugins() {
        let plugin = "version 2.0.0;
            circuit;
            @type field 2;
            @plugin mux_v0;
            @begin
            @end ";
        let plugin_cursor = &mut Cursor::new(plugin.as_bytes());
        let reader = RelationReader::new(plugin_cursor).unwrap();
        assert!(Proof::<InsecureVole>::validate_circuit_header(&reader).is_err());
    }

    #[test]
    fn header_cannot_include_conversions() {
        // The conversion is from self->self because adding an extra type is a different failure case
        let trivial_conversion = "version 2.0.0;
            circuit;
            @type field 2;
            @convert(@out: 0:1, @in: 0:1);
            @begin
            @end ";
        let conversion_cursor = &mut Cursor::new(trivial_conversion.as_bytes());
        let reader = RelationReader::new(conversion_cursor).unwrap();
        assert!(Proof::<InsecureVole>::validate_circuit_header(&reader).is_err());
    }

    #[test]
    fn header_cannot_include_non_boolean_fields() {
        let big_field = "version 2.0.0;
            circuit;
            @type field 2305843009213693951;
            @begin
            @end ";
        let big_field_cursor = &mut Cursor::new(big_field.as_bytes());
        let reader = RelationReader::new(big_field_cursor).unwrap();
        assert!(Proof::<InsecureVole>::validate_circuit_header(&reader).is_err());

        let extra_field = "version 2.0.0;
            circuit;
            @type field 2;
            @type field 2305843009213693951;
            @begin
            @end ";
        let extra_field_cursor = &mut Cursor::new(extra_field.as_bytes());
        let reader = RelationReader::new(extra_field_cursor).unwrap();
        assert!(Proof::<InsecureVole>::validate_circuit_header(&reader).is_err());
    }

    #[test]
    fn tiny_header_works() -> eyre::Result<()> {
        let tiny_header = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
            @end ";
        let tiny_header_cursor = &mut Cursor::new(tiny_header.as_bytes());
        let reader = RelationReader::new(tiny_header_cursor)?;
        assert!(Proof::<InsecureVole>::validate_circuit_header(&reader).is_ok());
        Ok(())
    }

    #[test]
    fn prove_doesnt_explode() -> Result<()> {
        // This doesn't test anything, per se. Just makes sure the prove algorithm runs without
        // borking on a valid input.
        let mini_circuit_bytes = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @mul(0: $0, $0);
              $2 <- @add(0: $0, $0);
            @end ";
        let mini_circuit = &mut Cursor::new(mini_circuit_bytes.as_bytes());

        let transcript = &mut Transcript::new(b"basic happy test transcript");

        let dir = tempdir()?;
        let private_input_path = dir.path().join("basic_happy_test_path");
        let mut private_input = File::create(private_input_path.clone())?;
        let private_input_bytes = "version 2.0.0;
            private_input;
            @type field 2;
            @begin
                < 1 >;
            @end";
        writeln!(private_input, "{}", private_input_bytes)?;

        let rng = &mut thread_rng();

        let proof = Proof::<InsecureVole>::prove::<_, _>(
            mini_circuit,
            &private_input_path,
            transcript,
            rng,
        )?;

        let verification_transcript = &mut Transcript::new(b"basic happy test transcript");
        assert!(proof.verify(verification_transcript).is_ok());

        Ok(())
    }
}
