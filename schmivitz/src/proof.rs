use eyre::{bail, Result};
use mac_n_cheese_sieve_parser::{text_parser::RelationReader, Number, Type};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use std::{
    io::{Read, Seek},
    iter::{repeat_with, zip},
    path::Path,
};
use swanky_field::{FiniteField, FiniteRing, IsSubFieldOf};
use swanky_field_binary::{F128b, F8b, F2};
use swanky_serialization::CanonicalSerialize;

use crate::{
    parameters::FIELD_SIZE,
    proof::{prover_preparer::ProverPreparer, prover_traverser::ProverTraverser},
    vole::{insecure::InsecureVole, RandomVole},
};

use self::verifier_traverser::VerifierTraverser;

mod prover_preparer;
mod prover_traverser;
mod verifier_traverser;

/// Zero-knowledge proof of knowledge of a circuit.
///
/// TODO #251: Add VOLE challenge to this type.
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
    /// Challenge generated after committing to the degree coefficients.
    /// TODO #251: This type might change depending on what is acutally needed to decommit VOLEs.
    decommitment_challenge: [u8; 16],
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
            .collect();

        // TODO #251: Add witness commitment to transcript here!!!
        transcript.append_message(b"commit to witness", b"todo: commit the actual value");

        // Generate challenges
        let witness_challenges = repeat_with(|| {
            let mut bytes = [0u8; 16];
            transcript.challenge_bytes(b"challenge part 2", &mut bytes);
            F128b::from_uniform_bytes(&bytes)
        })
        .take(witness_len)
        .collect();

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
        // into the proof. As a temporary placeholder, we manually get a challenge outside the
        // VOLE API.
        let partial_decommitment = voles.decommit(transcript);
        let mut wrong_decommitment_challenge = [0u8; 16];
        transcript.challenge_bytes(
            b"VOLE decommitment challenge (but done incorrectly)",
            &mut wrong_decommitment_challenge,
        );

        // Form the proof
        Ok(Self {
            witness_commitment,
            witness_challenges,
            degree_0_commitment,
            degree_1_commitment,
            decommitment_challenge: wrong_decommitment_challenge,
            partial_decommitment,
        })
    }

    fn extended_witness_length(&self) -> usize {
        self.witness_commitment.len()
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

impl Proof<InsecureVole> {
    /// This makes sure the proof is correctly formed e.g. everything is the right length.
    fn validate_proof(&self) -> Result<()> {
        // There should be one witness commitment for every element in the extended witness
        // The proof and the decommitted VOLEs should agree on what this size is
        if self.witness_commitment.len() != self.partial_decommitment.extended_witness_length() {
            bail!("Invalid proof: Did not commit to the same number of witnesses {} as there are VOLEs {}",
                self.witness_commitment.len(), self.partial_decommitment.extended_witness_length())
        }

        // There should be one challenge for every polynomial in the circuit. We can't tell
        // exactly how many that is without traversing the circuit, but it should be the total
        // number of witnesses less the public inputs
        if self.witness_challenges.len() > self.witness_commitment.len() {
            bail!(
                "Invalid proof: More challenges {} than we have witnesses to commit to {}",
                self.witness_challenges.len(),
                self.witness_commitment.len()
            )
        }

        // The partial decommitment must also be valid
        self.partial_decommitment.validate_commitments()
    }

    /// Verify the proof.
    ///
    pub fn verify<T>(&self, circuit: &mut T, transcript: &mut Transcript) -> Result<()>
    where
        T: Read + Seek + Clone,
    {
        self.validate_proof()?;

        // TODO #251: Add public values to transcript here!!!
        transcript.append_message(b"commit to public values", b"todo: commit properly");
        InsecureVole::update_transcript(transcript, self.extended_witness_length());

        // TODO #251: Squeeze first VOLE challenge and check it against the value in the proof

        // TODO #251: Add witness commitment to transcript here!!! The TODO is to abstract to a
        // method and actually put the witness commitment in.
        let _witness_commitment = self.witness_commitment.as_slice();
        transcript.append_message(b"commit to witness", b"todo: commit the actual value");

        // Generate challenges for each polynomial
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

        // TODO #251: Add a~, b~ to transcript!! The TODO is to abstract this to a method.
        transcript.append_message(
            b"b~: degree 0 commitment",
            &self.degree_0_commitment.to_bytes(),
        );
        transcript.append_message(
            b"a~: degree 1 commitment",
            &self.degree_1_commitment.to_bytes(),
        );

        // TODO #251: Squeeze expected decommitment challenge and check it against the value in the proof!
        // This should likely be a method on the decommitment or VOLE type instead of being hard-coded.
        let mut expected_decommitment_challenge = [0u8; 16];
        transcript.challenge_bytes(
            b"VOLE decommitment challenge (but done incorrectly)",
            &mut expected_decommitment_challenge,
        );
        if self.decommitment_challenge != expected_decommitment_challenge {
            bail!("Verification failed: VOLE challenge did not match expected value");
        }

        // Compute masked witnesses Q' = Q[..l] + d * Delta
        let d_delta = self
            .witness_commitment
            .iter()
            .map(|witness_com| {
                let witness_com = F8b::from(*witness_com);
                self.partial_decommitment
                    .verifier_key_array()
                    .map(|key| witness_com * key)
            })
            .collect::<Vec<_>>();
        let masked_witnesses = zip(self.partial_decommitment.witness_voles(), d_delta)
            .map(|(qs, dds)| {
                // NB: This unwrap is safe because we know the two input arrays are each exactly length 16.
                let masked_witness: [F8b; 16] = zip(qs, dds)
                    .map(|(q, dd)| q + dd)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                F8b::form_superfield(&masked_witness.into())
            })
            .collect::<Vec<_>>();

        // Combine mask VOLEs to get q*
        let validation_mask = combine(self.partial_decommitment.mask_voles());

        // Run circuit traversal and get the aggregate value (part of c~)
        let mut verifier_traverser = VerifierTraverser::new(
            expected_witness_challenges,
            self.partial_decommitment.verifier_key(),
            masked_witnesses,
        )?;
        let reader = RelationReader::new(circuit)?;
        reader.read(&mut verifier_traverser)?;
        let validation_aggregate = verifier_traverser.into_parts();

        // Finally, compute c~ = aggregate + q*
        let validation = validation_aggregate + validation_mask;

        // Check the main constraint of the proof!!
        let actual_validation = self.degree_1_commitment * self.partial_decommitment.verifier_key()
            + self.degree_0_commitment;
        if validation != actual_validation {
            bail!("Verification failed: proof responses were not consistent with decommited VOLEs and masked witnesses");
        }
        Ok(())
    }
}

/// Convert a list of field elements into a single 128-bit value.
///
/// Specifically, we compute
/// $` \sum_{i = 0}^{128} v_i X^i`$,
/// where $`X`$ is [`F128b::GENERATOR`], the generator for the field.
fn combine(values: [F128b; 128]) -> F128b {
    // Start with `X^0 = 1`
    let mut power = F128b::ONE;
    let mut acc = F128b::ZERO;

    for vi in values {
        acc += vi * power;
        power *= F128b::GENERATOR;
    }
    acc
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

    // Get a fresh transcript
    fn transcript() -> Transcript {
        Transcript::new(b"basic happy test transcript")
    }

    #[test]
    fn prove_doesnt_explode() -> Result<()> {
        let mini_circuit_bytes = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @mul(0: $0, $0);
              $2 <- @add(0: $0, $0);
            @end ";
        let mini_circuit = &mut Cursor::new(mini_circuit_bytes.as_bytes());

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
            &mut mini_circuit.clone(),
            &private_input_path,
            &mut transcript(),
            rng,
        )?;

        assert!(proof.verify(mini_circuit, &mut transcript()).is_ok());

        Ok(())
    }

    #[test]
    fn prove_works_on_slightly_larger_circuit() -> Result<()> {
        let small_circuit_bytes = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 ... $4 <- @private(0);
              $5 <- @add(0: $0, $0);
              $6 <- @add(0: $0, $1);
              $7 <- @add(0: $0, $2);
              $8 <- @add(0: $0, $3);
              $9 <- @add(0: $0, $4);
              $10 <- @mul(0: $0, $5);
              $11 <- @mul(0: $0, $6);
              $12 <- @mul(0: $0, $7);
              $13 <- @mul(0: $0, $8);
              $14 <- @mul(0: $0, $9);
            @end ";
        let small_circuit = &mut Cursor::new(small_circuit_bytes.as_bytes());

        let dir = tempdir()?;
        let private_input_path = dir.path().join("basic_happy_small_test_path");
        let mut private_input = File::create(private_input_path.clone())?;
        let private_input_bytes = "version 2.0.0;
            private_input;
            @type field 2;
            @begin
                < 1 >;
                < 0 >;
                < 1 >;
                < 0 >;
                < 1 >;
            @end ";
        writeln!(private_input, "{}", private_input_bytes)?;

        let rng = &mut thread_rng();

        let proof = Proof::<InsecureVole>::prove::<_, _>(
            &mut small_circuit.clone(),
            &private_input_path,
            &mut transcript(),
            rng,
        )?;

        assert!(proof.verify(small_circuit, &mut transcript()).is_ok());

        Ok(())
    }
}
