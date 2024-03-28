//! General-purpose VOLE-in-the-head proof.
//!
//! Much of the documentation refers to notation in "the paper"; this is referencing
//! Baum et al.[^vole].
//!
//! [^vole]: Carsten Baum, Lennart Braun, Cyprien Delpech de Saint Guilhem, Michael Klooß,
//! Emmanuela Orsini, Lawrence Roy, and Peter Scholl. [Publicly Verifiable Zero-Knowledge and
//! Post-Quantum Signatures from VOLE-in-the-head](https://eprint.iacr.org/2023/996). 2023.
//!
use eyre::{bail, Result};
use mac_n_cheese_sieve_parser::{text_parser::RelationReader, Number, Type};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use std::{
    io::{Read, Seek},
    iter::zip,
    path::Path,
};
use swanky_field::{FiniteField, FiniteRing, IsSubFieldOf};
use swanky_field_binary::{F128b, F8b, F2};

use crate::{
    parameters::FIELD_SIZE,
    proof::{prover_preparer::ProverPreparer, prover_traverser::ProverTraverser},
    vole::{insecure::InsecureVole, RandomVole},
};

use self::verifier_traverser::VerifierTraverser;

mod prover_preparer;
mod prover_preparer2;
mod prover_traverser;
mod prover_traverser2;
mod transcript;
mod verifier_traverser;

pub use prover_preparer2::ProverPreparer2;
pub use prover_traverser2::ProverTraverser2;

/// Zero-knowledge proof of knowledge of a circuit.
#[derive(Debug, Clone)]
pub struct Proof<Vole: RandomVole> {
    /// Challenge generated in VOLE creation.
    vole_challenge: Vole::VoleChallenge,
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
    /// Challenge generated to decommit to the VOLEs after committing to the degree coefficients.
    decommitment_challenge: Vole::VoleDecommitmentChallenge,
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

        let mut transcript = transcript::Transcript::from(transcript);

        // Evaluate the circuit in the clear to get the full witness and all wire values
        let mut circuit_preparer = ProverPreparer::new_from_path(private_input)?;
        reader.read(&mut circuit_preparer)?;
        let (witness, wire_values, challenge_count) = circuit_preparer.into_parts();

        // Update transcript with general public information
        transcript.append_public_values();

        // Get a set of random VOLEs, one for each value in the extended witness
        let (voles, vole_challenge) = Vole::create(witness.len(), transcript.as_mut(), rng);

        // Commit to extended witness (`d` in the paper)
        let witness_commitment: Vec<F2> = zip(witness, voles.witness_mask())
            .map(|(w, u)| w - u)
            .collect();

        // Add witness commitment to the transcript and generate a challenge for each polynomial
        transcript.append_witness_commitment(witness_commitment.as_slice());
        let witness_challenges = transcript.extract_witness_challenges(challenge_count);

        // Traverse circuit to compute the coefficients for the degree 0 and 1 terms for each
        // gate / polynomial (`A_i0` and `A_i1` in the paper) and start to aggregate these with
        // the challenges.
        let mut circuit_traverser = ProverTraverser::new(wire_values, witness_challenges, voles)?;
        RelationReader::new(circuit)?.read(&mut circuit_traverser)?;
        let (degree_0_aggregation, degree_1_aggregation, voles, witness_challenges) =
            circuit_traverser.into_parts()?;

        // Compute masks for the aggregated coefficients (`v*`, `u*` in the paper)
        let degree_0_mask = combine(voles.aggregate_commitment_masks());
        let degree_1_mask = combine(voles.aggregate_commitment_values());

        // Finish computing aggregated responses (`a~`, `b~` in the paper)
        let degree_0_commitment = degree_0_aggregation + degree_0_mask;
        let degree_1_commitment = degree_1_aggregation + degree_1_mask;

        // Add aggregated responses to transcript
        transcript.append_polynomial_commitments(&degree_0_commitment, &degree_1_commitment);

        // Decommit the VOLEs
        let (partial_decommitment, decommitment_challenge) = voles.decommit(transcript.as_mut());

        // Form the proof
        Ok(Self {
            vole_challenge,
            witness_commitment,
            witness_challenges,
            degree_0_commitment,
            degree_1_commitment,
            decommitment_challenge,
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
        let mut transcript = transcript::Transcript::from(transcript);

        // Add public values to transcript for both the overall proof...
        transcript.append_public_values();

        // ...and the specific VOLE instantiation, and get the VOLE challenge
        let expected_vole_challenge = InsecureVole::extract_vole_challenge(
            transcript.as_mut(),
            self.extended_witness_length(),
        );
        if self.vole_challenge != expected_vole_challenge {
            bail!("Verification failed: Vole challenge did not match expected value");
        }

        // Add witness commitment to transcript and generate challenges for each polynomial
        transcript.append_witness_commitment(self.witness_commitment.as_slice());
        let expected_witness_challenges =
            transcript.extract_witness_challenges(self.witness_challenges.len());
        if expected_witness_challenges != self.witness_challenges {
            bail!("Verification failed: Witness challenges did not match expected values");
        }

        // Add aggregated responses to the transcript
        transcript
            .append_polynomial_commitments(&self.degree_0_commitment, &self.degree_1_commitment);

        // Get the VOLE decommitment challenge and make sure it's valid
        let expected_decommitment_challenge =
            InsecureVole::extract_decommitment_challenge(transcript.as_mut());
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
            self.witness_challenges.clone(),
            self.partial_decommitment.verifier_key(),
            masked_witnesses,
        )?;
        let reader = RelationReader::new(circuit)?;
        reader.read(&mut verifier_traverser)?;
        let validation_aggregate = verifier_traverser.into_parts()?;

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
    use swanky_field::FiniteRing;
    use swanky_field_binary::F128b;
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

    // Create a proof for the given circuit and input.
    fn create_proof(
        circuit_bytes: &'static str,
        private_input_bytes: &'static str,
    ) -> (Result<Proof<InsecureVole>>, Cursor<&'static [u8]>) {
        let circuit = Cursor::new(circuit_bytes.as_bytes());

        let dir = tempdir().unwrap();
        let private_input_path = dir.path().join("schmivitz_private_inputs");
        let mut private_input = File::create(private_input_path.clone()).unwrap();
        writeln!(private_input, "{}", private_input_bytes).unwrap();

        let rng = &mut thread_rng();

        (
            Proof::<InsecureVole>::prove::<_, _>(
                &mut circuit.clone(),
                &private_input_path,
                &mut transcript(),
                rng,
            ),
            circuit,
        )
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
        let private_input_bytes = "version 2.0.0;
            private_input;
            @type field 2;
            @begin
                < 1 >;
            @end";

        let (proof, mut mini_circuit) = create_proof(mini_circuit_bytes, private_input_bytes);
        assert!(proof?.verify(&mut mini_circuit, &mut transcript()).is_ok());

        Ok(())
    }

    const SMALL_CIRCUIT: &str = "version 2.0.0;
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

    #[test]
    fn prove_works_on_slightly_larger_circuit() -> Result<()> {
        let private_input_bytes = "version 2.0.0;
            private_input;
            @type field 2;
            @begin
                < 1 >;
                < 1 >;
                < 1 >;
                < 0 >;
                < 0 >;
            @end ";

        let (proof, mut small_circuit) = create_proof(SMALL_CIRCUIT, private_input_bytes);
        assert!(proof?.verify(&mut small_circuit, &mut transcript()).is_ok());

        Ok(())
    }

    #[test]
    fn prover_and_verifier_must_input_the_same_transcript() -> Result<()> {
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

        // This uses the output of `transcript()` as-is to prove. This should work
        let (proof, mut small_circuit) = create_proof(SMALL_CIRCUIT, private_input_bytes);
        assert!(proof.is_ok());

        // If we use a different transcript to verify, it'll fail
        let transcript = &mut transcript();
        transcript.append_message(b"I am but a simple verifier", b"trying to be secure");
        assert!(proof?.verify(&mut small_circuit, transcript).is_err());

        Ok(())
    }

    #[test]
    fn proof_requires_exact_number_of_challenges() -> Result<()> {
        // Create a valid proof
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

        // Adding an extra challenge should fail
        let mut too_many_challenges = proof.clone();
        too_many_challenges
            .witness_challenges
            .push(F128b::random(rng));
        assert!(too_many_challenges
            .verify(&mut small_circuit.clone(), &mut transcript())
            .is_err());

        // Not having enough challenges should fail
        let mut too_few_challenges = proof.clone();
        too_few_challenges.witness_challenges.pop();
        assert!(too_few_challenges
            .verify(small_circuit, &mut transcript())
            .is_err());

        Ok(())
    }
}
