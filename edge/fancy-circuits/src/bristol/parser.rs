//! Methods for parsing and running Bristol Fashion files, as defined here:
//! <https://nigelsmart.github.io/MPC-Circuits>

use crate::bristol::{BinaryGate, BristolFashionCircuit};
use std::{io::BufRead, str::FromStr};
use swanky_error::{ErrorKind, Result, WrapErr, ensure, swanky_error};

/// Grab the next token from `parts`, failing if there is none.
fn next_token<'a>(parts: &mut impl Iterator<Item = &'a str>) -> Result<&'a str> {
    parts
        .next()
        .ok_or_else(|| swanky_error!(ErrorKind::OtherError, "Missing token"))
}

/// Grab the next token from `parts` and parse it as a [`u32`].
fn next_u32<'t>(parts: &mut impl Iterator<Item = &'t str>) -> Result<u32> {
    let s = next_token(parts)?;
    u32::from_str(s).wrap_err_with(ErrorKind::OtherError, || {
        format!("Failed to parse u32 from '{s}'")
    })
}

/// Translation from the wire numbering used by a circuit file to the canonical
/// numbering used by [`BristolFashionCircuit`], where the input wires come
/// first and the output wire of the `i`th gate is wire `ninputs + i`.
struct WireMap {
    /// Canonical wire index of each wire in the file, or `u32::MAX` if that wire
    /// has not been assigned a value yet.
    map: Vec<u32>,
    /// Canonical index to assign to the next wire that gets defined.
    next: u32,
}

impl WireMap {
    /// Build a [`WireMap`] for a circuit file on `nwires` wires, the first
    /// `ninputs` of which are the circuit's inputs.
    ///
    /// # Panics
    /// This panics if `ninputs <= nwires`.
    fn new(nwires: u32, ninputs: u32) -> Self {
        assert!(ninputs <= nwires);
        let mut map = vec![u32::MAX; nwires as usize];
        for (i, wire) in map.iter_mut().enumerate().take(ninputs as usize) {
            *wire = i as u32;
        }
        Self { map, next: ninputs }
    }

    /// Look up the canonical index of `wire`, failing if it has not been
    /// defined yet.
    fn get(&self, wire: u32) -> Result<u32> {
        let canonical = *self.map.get(wire as usize).ok_or_else(|| {
            swanky_error!(
                ErrorKind::OtherError,
                "Wire {wire} is out of range of the circuit's wire count"
            )
        })?;
        ensure!(
            canonical != u32::MAX,
            ErrorKind::OtherError,
            "Wire {} is used before it is defined",
            wire
        );
        Ok(canonical)
    }

    /// Assign the next canonical index to `wire`.
    fn set(&mut self, wire: u32) -> Result<()> {
        let canonical = self.map.get_mut(wire as usize).ok_or_else(|| {
            swanky_error!(
                ErrorKind::OtherError,
                "Wire {wire} is out of range of the circuit's wire count"
            )
        })?;
        *canonical = self.next;
        self.next += 1;
        Ok(())
    }
}

/// Parses a gate definition of the form
/// `<# input wires> <# output wires> <input wires...> <output wire> <gate type>`,
/// returning the resulting [`BinaryGate`]. The gate's wires are translated
/// through `wires`, whose output wire is defined as a side effect.
fn parse_gate(line: &str, wires: &mut WireMap) -> Result<BinaryGate> {
    let mut parts = line.split_whitespace();
    let ninput_wires = next_u32(&mut parts)?;
    let noutput_wires = next_u32(&mut parts)?;
    ensure!(
        noutput_wires == 1,
        ErrorKind::OtherError,
        "Expected one output wire, got {}",
        noutput_wires
    );
    let gate = match ninput_wires {
        1 => {
            let xref = wires.get(next_u32(&mut parts)?)?;
            let out = next_u32(&mut parts)?;
            let typ = next_token(&mut parts)?;
            ensure!(
                typ == "INV",
                ErrorKind::OtherError,
                "Unknown one-input gate type '{}'",
                typ
            );
            wires.set(out)?;
            BinaryGate::Inv { xref }
        }
        2 => {
            let xref = wires.get(next_u32(&mut parts)?)?;
            let yref = wires.get(next_u32(&mut parts)?)?;
            let out = next_u32(&mut parts)?;
            let typ = next_token(&mut parts)?;
            let gate = match typ {
                "AND" => BinaryGate::And { xref, yref },
                "XOR" => BinaryGate::Xor { xref, yref },
                typ => swanky_error::bail!(
                    ErrorKind::OtherError,
                    "Unknown two-input gate type '{}'",
                    typ
                ),
            };
            wires.set(out)?;
            gate
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

impl BristolFashionCircuit {
    /// Generate a new [`BristolFashionCircuit`] from the provided reader. The
    /// file must follow the Bristol Fashion format.
    pub(crate) fn parse_bristol_fashion(mut reader: impl BufRead) -> Result<Self> {
        // Parse first line: "ngates nwires\n".
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .wrap_err(ErrorKind::OtherError, "Failed to read line")?;
        let mut parts = line.split_whitespace();
        let ngates = next_u32(&mut parts)?;
        let nwires = next_u32(&mut parts)?;

        // Parse second line: "ninputs input1 input2 ...\n".
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .wrap_err(ErrorKind::OtherError, "Failed to read line")?;
        let mut parts = line.split_whitespace();

        let ninputs = next_u32(&mut parts)?;
        let mut ninputs_total = 0;
        for _ in 0..ninputs {
            let ninputs = next_u32(&mut parts)?;
            ninputs_total += ninputs;
        }

        // Parse third line: nparties_output output_bits_party1 output_bits_party2 ...\n
        // Note: nparties_output can be different from nparties (input parties)
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .wrap_err(ErrorKind::OtherError, "Failed to read line")?;
        let mut parts = line.split_whitespace();
        let noutputs = next_u32(&mut parts)?;
        let mut noutputs_total = 0;
        for _ in 0..noutputs {
            let noutputs = next_u32(&mut parts)?;
            noutputs_total += noutputs;
        }

        let mut circ = Self::new(ninputs_total as usize, Some(ngates as usize));
        let mut wires = WireMap::new(nwires, ninputs_total);

        // Parse gate definitions.
        for line in reader.lines() {
            let line = line.wrap_err(ErrorKind::OtherError, "Failed to read line")?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let gate = parse_gate(line, &mut wires).wrap_err_with(ErrorKind::OtherError, || {
                format!("Invalid gate definition: {line}")
            })?;
            circ.gates.push(gate);
        }

        // Process outputs, which are the last `noutputs_total` wires of the
        // file, in reverse order.
        for i in (0..noutputs_total).rev() {
            circ.output_refs
                .push(wires.get(nwires - noutputs_total + i)?);
        }

        circ.batch_gates_by_type();
        Ok(circ)
    }
}

#[cfg(test)]
mod tests {
    use crate::bristol::BristolFashionCircuit;
    use std::io::Cursor;

    #[test]
    fn bristol_fashion_parser_works() {
        // Tests all the circuits in the `circuits/bristol-fashion` directory.

        // Test AES-128 circuit.
        let result = BristolFashionCircuit::parse_bristol_fashion(Cursor::<&'static [u8]>::new(
            include_bytes!("../../circuits/bristol-fashion/aes_128.txt"),
        ));
        assert!(result.is_ok());
        let circuit = result.unwrap();
        // AES-128: 2 input values with 128 bits each = 256 inputs total.
        assert_eq!(circuit.ninputs, 256);
        // AES-128: 1 output value with 128 bits output = 128 outputs total.
        assert_eq!(circuit.output_refs.len(), 128);
        // Verify circuit has gates.
        assert!(!circuit.gates.is_empty());

        // Test SHA-256 circuit.
        let result = BristolFashionCircuit::parse_bristol_fashion(Cursor::<&'static [u8]>::new(
            include_bytes!("../../circuits/bristol-fashion/sha256.txt"),
        ));
        assert!(result.is_ok());
        let circuit = result.unwrap();
        // SHA-256: 2 parties with 512 + 256 = 768 inputs total.
        assert_eq!(circuit.ninputs, 768);
        // SHA-256: 1 party with 256 bits output = 256 outputs total.
        assert_eq!(circuit.output_refs.len(), 256);
        // Verify circuit has gates.
        assert!(!circuit.gates.is_empty());
    }
}
