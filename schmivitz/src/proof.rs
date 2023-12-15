use eyre::{bail, Result};
use mac_n_cheese_sieve_parser::{text_parser::RelationReader, Number, Type};
use std::io::{Read, Seek};

use crate::parameters::FIELD_SIZE;

/// Zero-knowledge proof of knowledge of a circuit.
#[derive(Debug, Clone)]
pub struct Proof {}

impl Proof {
    /// Create a proof of knowledge of a witness that satisfies the given circuit.
    pub fn prove<T: Read + Seek>(circuit: &mut T) -> Result<Self> {
        let reader = RelationReader::new(circuit)?;
        Self::validate_circuit_header(reader)?;

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
    fn validate_circuit_header<T: Read + Seek>(circuit_reader: RelationReader<T>) -> Result<()> {
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
    use std::io::Cursor;

    use crate::Proof;

    #[test]
    fn header_cannot_include_plugins() {
        let plugin = "version 2.0.0;
            circuit;
            @type field 2;
            @plugin mux_v0;
            @begin
            @end ";
        let plugin_cursor = &mut Cursor::new(plugin.as_bytes());
        assert!(Proof::prove(plugin_cursor).is_err());
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
        assert!(Proof::prove(conversion_cursor).is_err());
    }

    #[test]
    fn header_cannot_include_non_boolean_fields() {
        let big_field = "version 2.0.0;
            circuit;
            @type field 2305843009213693951;
            @begin
            @end ";
        let big_field_cursor = &mut Cursor::new(big_field.as_bytes());
        assert!(Proof::prove(big_field_cursor).is_err());

        let extra_field = "version 2.0.0;
            circuit;
            @type field 2;
            @type field 2305843009213693951;
            @begin
            @end ";
        let extra_field_cursor = &mut Cursor::new(extra_field.as_bytes());
        assert!(Proof::prove(extra_field_cursor).is_err());
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn tiny_header_works() {
        let tiny_header = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
            @end ";
        let tiny_header_cursor = &mut Cursor::new(tiny_header.as_bytes());

        // The failure mode here will need to change once we actually do something in `prove`.
        // The panic we expect indicates that we got past the circuit validation method.
        let result = Proof::prove(tiny_header_cursor);
        assert!(result.is_ok());
    }
}
