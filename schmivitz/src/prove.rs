use eyre::{bail, Result};
use mac_n_cheese_sieve_parser::{text_parser::RelationReader, Number, Type};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use std::{
    io::{Read, Seek},
    path::Path,
};

use crate::{
    parameters::{self, FIELD_SIZE},
    prove::witness_counter::VoleCircuitPreparer,
    vole::RandomVole,
};

pub(crate) mod circuit_traverser;
pub(crate) mod witness_counter;

/// Zero-knowledge proof of knowledge of a circuit.
#[derive(Debug, Clone)]
pub struct Proof {}

impl Proof {
    /// Create a proof of knowledge of a witness that satisfies the given circuit.
    pub fn prove<T, R, Vole>(
        circuit: &mut T,
        private_input: &Path,
        _transcript: &mut Transcript,
        _rng: R,
    ) -> Result<Self>
    where
        T: Read + Seek,
        R: CryptoRng + RngCore,
        Vole: RandomVole,
    {
        let reader = RelationReader::new(circuit)?;
        Self::validate_circuit_header(&reader)?;

        // Check the circuit for the number of extended-witness-contributing gates
        let mut extended_witness_counter = VoleCircuitPreparer::new_from_path(private_input)?;
        reader.read(&mut extended_witness_counter)?;
        println!(
            "The extended witness size is {}",
            extended_witness_counter.count()
        );

        // Get the number of VOLEs by adding extended witness count to r * tau
        println!(
            "The total number of required VOLEs is {}",
            extended_witness_counter.count()
                + (parameters::VOLE_SIZE_PARAM * parameters::REPETITION_PARAM)
        );

        todo!()
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
        assert!(Proof::validate_circuit_header(&reader).is_err());
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
        assert!(Proof::validate_circuit_header(&reader).is_err());
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
        assert!(Proof::validate_circuit_header(&reader).is_err());

        let extra_field = "version 2.0.0;
            circuit;
            @type field 2;
            @type field 2305843009213693951;
            @begin
            @end ";
        let extra_field_cursor = &mut Cursor::new(extra_field.as_bytes());
        let reader = RelationReader::new(extra_field_cursor).unwrap();
        assert!(Proof::validate_circuit_header(&reader).is_err());
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
        assert!(Proof::validate_circuit_header(&reader).is_ok());
        Ok(())
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn prove_doesnt_explode() {
        assert!(prove_doesnt_explode_result().is_ok())
    }

    fn prove_doesnt_explode_result() -> Result<()> {
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

        let _proof =
            Proof::prove::<_, _, InsecureVole>(mini_circuit, &private_input_path, transcript, rng)?;

        Ok(())
    }
}
