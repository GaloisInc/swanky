//! Functions for parsing and running circuit files.
//!
//! This module provides parsers for two Bristol circuit formats:
//!
//! - **Bristol Format**: The original format:
//!   <https://nigelsmart.github.io/MPC-Circuits/old-circuits.html>
//! - **Bristol Fashion**: The new format: <https://nigelsmart.github.io/MPC-Circuits>

use crate::{BinaryCircuit, BinaryGate};
use std::{io::BufRead, str::FromStr};
use swanky_error::{ErrorKind, Result, WrapErr, ensure, swanky_error};

/// Grab the next token from `parts`, failing if there is none.
fn next_token<'a>(parts: &mut impl Iterator<Item = &'a str>) -> Result<&'a str> {
    parts
        .next()
        .ok_or_else(|| swanky_error!(ErrorKind::OtherError, "Missing token"))
}

/// Grab the next token from `parts` and parse it as a [`usize`].
fn next_usize<'t>(parts: &mut impl Iterator<Item = &'t str>) -> Result<usize> {
    let s = next_token(parts)?;
    usize::from_str(s).wrap_err_with(ErrorKind::OtherError, || {
        format!("Failed to parse usize from '{s}'")
    })
}

/// Parses a gate definition of the form
/// `<# input wires> <# output wires> <input wires...> <output wire> <gate type>`,
/// returning the resulting [`BinaryGate`].
fn parse_gate(line: &str) -> Result<BinaryGate> {
    let mut parts = line.split_whitespace();
    let ninput_wires = next_usize(&mut parts)?;
    let noutput_wires = next_usize(&mut parts)?;
    ensure!(
        noutput_wires == 1,
        ErrorKind::OtherError,
        "Expected one output wire, got {}",
        noutput_wires
    );
    let gate = match ninput_wires {
        1 => {
            let xref = next_usize(&mut parts)?;
            let out = next_usize(&mut parts)?;
            let typ = next_token(&mut parts)?;
            ensure!(
                typ == "INV",
                ErrorKind::OtherError,
                "Unknown one-input gate type '{}'",
                typ
            );
            BinaryGate::Inv { xref, out }
        }
        2 => {
            let xref = next_usize(&mut parts)?;
            let yref = next_usize(&mut parts)?;
            let out = next_usize(&mut parts)?;
            let typ = next_token(&mut parts)?;
            match typ {
                "AND" => BinaryGate::And { xref, yref, out },
                "XOR" => BinaryGate::Xor { xref, yref, out },
                typ => swanky_error::bail!(
                    ErrorKind::OtherError,
                    "Unknown two-input gate type '{}'",
                    typ
                ),
            }
        }
        n => swanky_error::bail!(
            ErrorKind::OtherError,
            "Unsupported number of input wires: {}",
            n
        ),
    };
    ensure!(
        parts.next().is_none(),
        ErrorKind::OtherError,
        "Trailing data in gate definition: {}",
        line
    );
    Ok(gate)
}

impl BinaryCircuit {
    /// Generate a new [`BinaryCircuit`] from the provided reader. The file must
    /// follow the Bristol Fashion format.
    pub fn parse_bristol_fashion(mut reader: impl BufRead) -> Result<Self> {
        // Parse first line: "ngates nwires\n".
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .wrap_err(ErrorKind::OtherError, "Failed to read line")?;
        let mut parts = line.split_whitespace();
        let ngates = next_usize(&mut parts)?;
        let nwires = next_usize(&mut parts)?;

        // Parse second line: "ninputs input1 input2 ...\n".
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .wrap_err(ErrorKind::OtherError, "Failed to read line")?;
        let mut parts = line.split_whitespace();

        let ninputs = next_usize(&mut parts)?;
        let mut ninputs_total = 0;
        for _ in 0..ninputs {
            let ninputs = next_usize(&mut parts)?;
            ninputs_total += ninputs;
        }

        // Parse third line: nparties_output output_bits_party1 output_bits_party2 ...\n
        // Note: nparties_output can be different from nparties (input parties)
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .wrap_err(ErrorKind::OtherError, "Failed to read line")?;
        let mut parts = line.split_whitespace();
        let noutputs = next_usize(&mut parts)?;
        let mut noutputs_total = 0;
        for _ in 0..noutputs {
            let noutputs = next_usize(&mut parts)?;
            noutputs_total += noutputs;
        }

        let mut circ = Self::new(Some(ngates));

        // Process inputs.
        for i in 0..ninputs_total {
            circ.input_refs.push(i);
        }
        // Process outputs.
        for i in (0..noutputs_total).rev() {
            circ.output_refs.push(nwires - noutputs_total + i);
        }

        // Parse gate definitions (same as Bristol Format).
        for line in reader.lines() {
            let line = line.wrap_err(ErrorKind::OtherError, "Failed to read line")?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let gate = parse_gate(line).wrap_err_with(ErrorKind::OtherError, || {
                format!("Invalid gate definition: {line}")
            })?;
            circ.gates.push(gate);
        }
        Ok(circ)
    }

    /// Generates a new [`BinaryCircuit`] from the provided reader. The file
    /// must follow the Bristol Format given here:
    /// <https://nigelsmart.github.io/MPC-Circuits/old-circuits.html>.
    pub fn parse_bristol_format(mut reader: impl BufRead) -> Result<Self> {
        // Parse first line: ngates nwires\n
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .wrap_err(ErrorKind::OtherError, "Failed to read line")?;
        let mut parts = line.split_whitespace();
        let ngates = next_usize(&mut parts)?;
        let nwires = next_usize(&mut parts)?;
        ensure!(
            parts.next().is_none(),
            ErrorKind::OtherError,
            "Trailing data in gate and wire count line: {}",
            line.trim()
        );

        // Parse second line: n1 n2 n3\n
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .wrap_err(ErrorKind::OtherError, "Failed to read line")?;
        let mut parts = line.split_whitespace();
        let ngarbler_inputs = next_usize(&mut parts)?;
        let nevaluator_inputs = next_usize(&mut parts)?;
        let noutputs = next_usize(&mut parts)?;
        ensure!(
            parts.next().is_none(),
            ErrorKind::OtherError,
            "Trailing data in input and output count line: {}",
            line.trim()
        );

        // Parse third line: \n
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .wrap_err(ErrorKind::OtherError, "Failed to read line")?;
        ensure!(
            line.trim().is_empty(),
            ErrorKind::OtherError,
            "Expected an empty line, got: {}",
            line.trim()
        );

        let mut circ = Self::new(Some(ngates));

        // Process inputs.
        for i in 0..ngarbler_inputs + nevaluator_inputs {
            circ.input_refs.push(i);
        }
        // Process outputs.
        for i in 0..noutputs {
            circ.output_refs.push(nwires - noutputs + i);
        }
        // Parse gate definitions (same as Bristol Fashion).
        for line in reader.lines() {
            let line = line.wrap_err(ErrorKind::OtherError, "Failed to read line")?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let gate = parse_gate(line).wrap_err_with(ErrorKind::OtherError, || {
                format!("Invalid gate definition: {line}")
            })?;
            circ.gates.push(gate);
        }
        Ok(circ)
    }
}

#[cfg(test)]
mod tests {
    use crate::BinaryCircuit;
    use std::io::Cursor;

    #[test]
    fn bristol_format_parser_works() {
        // Tests all the circuits in the `circuits/bristol-format` directory.

        let result = BinaryCircuit::parse_bristol_format(Cursor::<&'static [u8]>::new(
            include_bytes!("../../circuits/bristol-format/adder_32bit.txt"),
        ));
        assert!(result.is_ok());

        let result = BinaryCircuit::parse_bristol_format(Cursor::<&'static [u8]>::new(
            include_bytes!("../../circuits/bristol-format/AES-non-expanded.txt"),
        ));
        assert!(result.is_ok());

        let result = BinaryCircuit::parse_bristol_format(Cursor::<&'static [u8]>::new(
            include_bytes!("../../circuits/bristol-format/sha-1.txt"),
        ));
        assert!(result.is_ok());

        let result = BinaryCircuit::parse_bristol_format(Cursor::<&'static [u8]>::new(
            include_bytes!("../../circuits/bristol-format/sha-256.txt"),
        ));
        assert!(result.is_ok());
    }

    #[test]
    fn bristol_fashion_parser_works() {
        // Tests all the circuits in the `circuits/bristol-fashion` directory.

        // Test AES-128 circuit.
        let result = BinaryCircuit::parse_bristol_fashion(Cursor::<&'static [u8]>::new(
            include_bytes!("../../circuits/bristol-fashion/aes_128.txt"),
        ));
        assert!(result.is_ok());
        let circuit = result.unwrap();
        // AES-128: 2 input values with 128 bits each = 256 inputs total.
        assert_eq!(circuit.input_refs.len(), 256);
        // AES-128: 1 output value with 128 bits output = 128 outputs total.
        assert_eq!(circuit.output_refs.len(), 128);
        // Verify circuit has gates.
        assert!(!circuit.gates.is_empty());

        // Test SHA-256 circuit.
        let result = BinaryCircuit::parse_bristol_fashion(Cursor::<&'static [u8]>::new(
            include_bytes!("../../circuits/bristol-fashion/sha256.txt"),
        ));
        assert!(result.is_ok());
        let circuit = result.unwrap();
        // SHA-256: 2 parties with 512 + 256 = 768 inputs total
        assert_eq!(circuit.input_refs.len(), 768);
        // SHA-256: 1 party with 256 bits output = 256 outputs total
        assert_eq!(circuit.output_refs.len(), 256);
        // Verify circuit has gates
        assert!(!circuit.gates.is_empty());
    }
}
