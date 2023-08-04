//! This module implements a reader for "Bristol Fashion" circuit definition files.

use std::io::BufRead;
use std::str::SplitWhitespace;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O Error: `{0}`")]
    IOError(#[from] std::io::Error),
    #[error("Parse Error (Int): `{0}`")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("Parse Error (Bristol): `{0}`")]
    ParseBristolError(String),
}

pub type Wire = u64;

#[derive(Debug, Copy, Clone)]
pub enum Gate {
    XOR { a: Wire, b: Wire, out: Wire },
    AND { a: Wire, b: Wire, out: Wire },
    INV { a: Wire, out: Wire },
    EQ { lit: bool, out: Wire },
    EQW { a: Wire, out: Wire },
}

/// A Bristol Fashion circuit.
#[derive(Default, Debug, Clone)]
pub struct Circuit {
    /// The number of gates in this circuit.    
    ngates: u64,
    /// The number of wires in this circuit.    
    nwires: u64,
    /// The sizes of each input to this circuit.
    /// For example, `vec![64, 64]` denotes a circuit with
    /// two inputs of `64` bits each.    
    input_sizes: Vec<u64>,
    /// The sizes of each output of this circuit.
    /// For example, `vec![64]` denotes a circuit with
    /// one output of `64` bits.    
    output_sizes: Vec<u64>,
    /// A topologically sorted list of gates.
    gates: Vec<Gate>,
}

impl Circuit {
    pub fn ngates(&self) -> u64 {
        self.ngates
    }

    pub fn nwires(&self) -> u64 {
        self.nwires
    }

    pub fn into_input_sizes(self) -> Vec<u64> {
        self.input_sizes
    }

    pub fn input_sizes(&self) -> &Vec<u64> {
        &self.input_sizes
    }

    pub fn input_sizes_mut(&mut self) -> &mut Vec<u64> {
        &mut self.input_sizes
    }

    pub fn into_output_sizes(self) -> Vec<u64> {
        self.output_sizes
    }

    pub fn output_sizes(&self) -> &Vec<u64> {
        &self.output_sizes
    }

    pub fn output_sizes_mut(&mut self) -> &mut Vec<u64> {
        &mut self.output_sizes
    }

    pub fn into_gates(self) -> Vec<Gate> {
        self.gates
    }

    pub fn gates(&self) -> &Vec<Gate> {
        &self.gates
    }

    pub fn gates_mut(&mut self) -> &mut Vec<Gate> {
        &mut self.gates
    }

    fn count_gates<F>(&self, f: F) -> u64
    where
        F: FnMut(&Gate) -> bool,
    {
        self.gates
            .iter()
            .copied()
            .filter(f)
            .count()
            .try_into()
            .unwrap()
    }

    /// The number of XOR gates in this circuit.
    pub fn nxor(&self) -> u64 {
        self.count_gates(|g| matches!(g, Gate::XOR { .. }))
    }

    /// The number of AND gates in this circuit.
    pub fn nand(&self) -> u64 {
        self.count_gates(|g| matches!(g, Gate::AND { .. }))
    }

    /// The number of INV gates in this circuit.
    pub fn ninv(&self) -> u64 {
        self.count_gates(|g| matches!(g, Gate::INV { .. }))
    }

    /// The number of EQ gates in this circuit.
    pub fn neq(&self) -> u64 {
        self.count_gates(|g| matches!(g, Gate::EQ { .. }))
    }

    /// The number of EQW gates in this circuit.
    pub fn neqw(&self) -> u64 {
        self.count_gates(|g| matches!(g, Gate::EQW { .. }))
    }
}

struct Reader<R: BufRead> {
    reader: R,
    line: String,
    row: usize,
}

impl<R: BufRead> Reader<R> {
    fn new(reader: R) -> Self {
        let line = String::new();
        let row = 0;
        Self { reader, line, row }
    }

    fn next_line(&mut self) -> Result<Option<SplitWhitespace>, Error> {
        self.line.clear();
        let n = self.reader.read_line(&mut self.line)?;
        self.row += 1;
        Ok(if n != 0 {
            Some(self.line.split_whitespace())
        } else {
            None
        })
    }

    fn expect_line(&mut self) -> Result<SplitWhitespace, Error> {
        let row = self.row;
        let ret = self.next_line()?;
        ret.ok_or_else(|| Error::ParseBristolError(format!("unexpected EOF on line {}", row)))
    }

    fn read_u64(tokens: &mut SplitWhitespace, msg: &str) -> Result<u64, Error> {
        tokens
            .next()
            .ok_or_else(|| Error::ParseBristolError(msg.to_string()))?
            .parse::<u64>()
            .map_err(Error::from)
    }

    fn read_bool(tokens: &mut SplitWhitespace, msg: &str) -> Result<bool, Error> {
        let x = tokens
            .next()
            .ok_or_else(|| Error::ParseBristolError(msg.to_string()))?
            .parse::<u8>()?;
        Self::parsing_assert(x == 0 || x == 1, format!("expected 0 or 1, but got {}", x))?;
        Ok(if x == 0 { false } else { true })
    }

    fn read_gate_kind<'a>(tokens: &mut SplitWhitespace<'a>) -> Result<&'a str, Error> {
        tokens.next_back().ok_or_else(|| {
            Error::ParseBristolError("unexpected EOL, expected gate kind".to_string())
        })
    }

    fn read_ngates(tokens: &mut SplitWhitespace) -> Result<u64, Error> {
        Self::read_u64(tokens, "unexpected EOL, expected ngates")
    }

    fn read_nwires(tokens: &mut SplitWhitespace) -> Result<u64, Error> {
        Self::read_u64(tokens, "unexpected EOL, expected nwires")
    }

    fn read_ninputs(tokens: &mut SplitWhitespace) -> Result<u64, Error> {
        Self::read_u64(tokens, "unexpected EOL, expected ninputs")
    }

    fn read_input_size(tokens: &mut SplitWhitespace) -> Result<u64, Error> {
        Self::read_u64(tokens, "unexpected EOL, expected input size")
    }

    fn read_noutputs(tokens: &mut SplitWhitespace) -> Result<u64, Error> {
        Self::read_u64(tokens, "unexpected EOL, expected noutputs")
    }

    fn read_output_size(tokens: &mut SplitWhitespace) -> Result<u64, Error> {
        Self::read_u64(tokens, "unexpected EOL, expected output size")
    }

    fn read_gate_input_arity(tokens: &mut SplitWhitespace) -> Result<u64, Error> {
        Self::read_u64(tokens, "unexpected EOL, expected gate input arity")
    }

    fn read_gate_output_arity(tokens: &mut SplitWhitespace) -> Result<u64, Error> {
        Self::read_u64(tokens, "unexpected EOL, expected gate output arity")
    }

    fn read_gate_input(tokens: &mut SplitWhitespace) -> Result<u64, Error> {
        Self::read_u64(tokens, "unexpected EOL, expected gate input")
    }

    fn read_gate_input_lit(tokens: &mut SplitWhitespace) -> Result<bool, Error> {
        Self::read_bool(tokens, "unexpected EOL, expected gate input lit")
    }

    fn read_gate_output(tokens: &mut SplitWhitespace) -> Result<u64, Error> {
        Self::read_u64(tokens, "unexpected EOL, expected gate output")
    }

    fn parsing_assert(cond: bool, msg: String) -> Result<(), Error> {
        if cond {
            Ok(())
        } else {
            Err(Error::ParseBristolError(msg))
        }
    }

    fn read_binary_gate(tokens: &mut SplitWhitespace) -> Result<(Wire, Wire, Wire), Error> {
        let in_arity = Self::read_gate_input_arity(tokens)?;
        Self::parsing_assert(
            in_arity == 2,
            format!("unexpected input arity, expected 2 but got {}", in_arity),
        )?;
        let out_arity = Self::read_gate_output_arity(tokens)?;
        Self::parsing_assert(
            out_arity == 1,
            format!("unexpected output arity, expected 1 but got {}", out_arity),
        )?;
        let a = Self::read_gate_input(tokens)?;
        let b = Self::read_gate_input(tokens)?;
        let out = Self::read_gate_output(tokens)?;
        let _ = Self::read_eol(tokens)?;
        Ok((a, b, out))
    }

    fn read_unary_gate(tokens: &mut SplitWhitespace) -> Result<(Wire, Wire), Error> {
        let in_arity = Self::read_gate_input_arity(tokens)?;
        Self::parsing_assert(
            in_arity == 1,
            format!("unexpected input arity, expected 1 but got {}", in_arity),
        )?;
        let out_arity = Self::read_gate_output_arity(tokens)?;
        Self::parsing_assert(
            out_arity == 1,
            format!("unexpected output arity, expected 1 but got {}", out_arity),
        )?;
        let a = Self::read_gate_input(tokens)?;
        let out = Self::read_gate_output(tokens)?;
        let _ = Self::read_eol(tokens)?;
        Ok((a, out))
    }

    fn read_eq_gate(tokens: &mut SplitWhitespace) -> Result<(bool, Wire), Error> {
        let in_arity = Self::read_gate_input_arity(tokens)?;
        Self::parsing_assert(
            in_arity == 1,
            format!("unexpected input arity, expected 1 but got {}", in_arity),
        )?;
        let out_arity = Self::read_gate_output_arity(tokens)?;
        Self::parsing_assert(
            out_arity == 1,
            format!("unexpected output arity, expected 1 but got {}", out_arity),
        )?;
        let lit = Self::read_gate_input_lit(tokens)?;
        let out = Self::read_gate_output(tokens)?;
        let _ = Self::read_eol(tokens)?;
        Ok((lit, out))
    }

    fn read_eol(tokens: &mut SplitWhitespace) -> Result<(), Error> {
        let x = tokens.next();
        match x {
            Some(_) => Err(Error::ParseBristolError(
                "unexpected token, expected EOL".to_string(),
            )),
            None => Ok(()),
        }
    }

    fn read(mut self) -> Result<Circuit, Error> {
        // Read number of gates (`ngates`) and number of wires (`nwires`) from first line
        let mut tokens = self.expect_line()?;
        let ngates = Self::read_ngates(&mut tokens)?;
        let nwires = Self::read_nwires(&mut tokens)?;
        let _ = Self::read_eol(&mut tokens)?;

        // Read number of inputs and sizes from second line
        let mut tokens = self.expect_line()?;
        let ninputs = Self::read_ninputs(&mut tokens)?;
        let mut input_sizes = Vec::with_capacity(usize::try_from(ninputs).unwrap());
        for _ in 0..ninputs {
            let input_size = Self::read_input_size(&mut tokens)?;
            input_sizes.push(input_size);
        }
        let _ = Self::read_eol(&mut tokens)?;

        // Read number of outputs and sizes from third line
        let mut tokens = self.expect_line()?;
        let noutputs = Self::read_noutputs(&mut tokens)?;
        let mut output_sizes = Vec::with_capacity(usize::try_from(noutputs).unwrap());
        for _ in 0..noutputs {
            let output_size = Self::read_output_size(&mut tokens)?;
            output_sizes.push(output_size);
        }
        let _ = Self::read_eol(&mut tokens)?;

        // Skip an empty line
        let mut tokens = self.expect_line()?;
        let _ = Self::read_eol(&mut tokens)?;

        // Read gates from remaining lines
        let mut gates: Vec<Gate> = Vec::with_capacity(usize::try_from(ngates).unwrap());
        for i in 0..ngates {
            let mut tokens = self.expect_line()?;
            let gate_kind = Self::read_gate_kind(&mut tokens)?;
            match gate_kind {
                "XOR" => {
                    let (a, b, out) = Self::read_binary_gate(&mut tokens)?;
                    gates.push(Gate::XOR { a, b, out });
                }
                "AND" => {
                    let (a, b, out) = Self::read_binary_gate(&mut tokens)?;
                    gates.push(Gate::AND { a, b, out });
                }
                "INV" => {
                    let (a, out) = Self::read_unary_gate(&mut tokens)?;
                    gates.push(Gate::INV { a, out });
                }
                "EQW" => {
                    let (a, out) = Self::read_unary_gate(&mut tokens)?;
                    gates.push(Gate::EQW { a, out });
                }
                "EQ" => {
                    let (lit, out) = Self::read_eq_gate(&mut tokens)?;
                    gates.push(Gate::EQ { lit, out });
                }
                "MAND" => {
                    let error_msg = format!(
                        "unexpected gate kind on line {}: MAND only supported by extended format",
                        5 + i
                    );
                    return Err(Error::ParseBristolError(error_msg));
                }
                _ => {
                    let error_msg =
                        format!("unexpected gate kind on line {}: {}", 5 + i, gate_kind);
                    return Err(Error::ParseBristolError(error_msg));
                }
            }
        }

        // Skip trailing empty lines, but make sure they are empty
        loop {
            let tokens = self.next_line()?;
            match tokens {
                None => {
                    break;
                }
                Some(mut tokens) => {
                    let _ = Self::read_eol(&mut tokens)?;
                }
            }
        }

        Ok(Circuit {
            ngates,
            nwires,
            input_sizes,
            output_sizes,
            gates,
        })
    }
}

/// Parses a reader formatted as Bristol Fashion into a `Circuit`.
/// Produces an I/O error on failure to read, and a parse error if
/// the reader is not well-formed Bristol Fashion.
pub fn read<R: BufRead>(reader: R) -> Result<Circuit, Error> {
    Reader::new(reader).read()
}

pub mod circuits;

#[cfg(test)]
mod tests {
    use super::*;
    use circuits::*;

    struct ReadSpec {
        bristol: fn() -> Circuit,
        ngates: u64,
        nwires: u64,
        input_sizes: Vec<u64>,
        output_sizes: Vec<u64>,
        nxor: u64,
        nand: u64,
        ninv: u64,
        neq: u64,
        neqw: u64,
    }

    fn test_read(spec: &ReadSpec) {
        let bristol = (spec.bristol)();
        assert_eq!(bristol.ngates, spec.ngates);
        assert_eq!(bristol.nwires, spec.nwires);
        assert_eq!(bristol.input_sizes.clone(), spec.input_sizes);
        assert_eq!(bristol.output_sizes.clone(), spec.output_sizes);
        assert_eq!(bristol.nxor(), spec.nxor);
        assert_eq!(bristol.nand(), spec.nand);
        assert_eq!(bristol.ninv(), spec.ninv);
        assert_eq!(bristol.neq(), spec.neq);
        assert_eq!(bristol.neqw(), spec.neqw);
    }

    #[test]
    pub(crate) fn test_read_add64() {
        let spec = ReadSpec {
            bristol: add64,
            ngates: 376,
            nwires: 504,
            input_sizes: vec![64, 64],
            output_sizes: vec![64],
            nxor: 313,
            nand: 63,
            ninv: 0,
            neq: 0,
            neqw: 0,
        };

        test_read(&spec)
    }

    #[test]
    pub(crate) fn test_read_sub64() {
        let spec = ReadSpec {
            bristol: sub64,
            ngates: 439,
            nwires: 567,
            input_sizes: vec![64, 64],
            output_sizes: vec![64],
            nxor: 313,
            nand: 63,
            ninv: 63,
            neq: 0,
            neqw: 0,
        };

        test_read(&spec)
    }

    #[test]
    pub(crate) fn test_read_neg64() {
        let spec = ReadSpec {
            bristol: neg64,
            ngates: 190,
            nwires: 254,
            input_sizes: vec![64],
            output_sizes: vec![64],
            nxor: 63,
            nand: 62,
            ninv: 64,
            neq: 0,
            neqw: 1,
        };

        test_read(&spec)
    }

    #[test]
    pub(crate) fn test_read_mul64() {
        let spec = ReadSpec {
            bristol: mul64,
            ngates: 13675,
            nwires: 13803,
            input_sizes: vec![64, 64],
            output_sizes: vec![64],
            nxor: 9642,
            nand: 4033,
            ninv: 0,
            neq: 0,
            neqw: 0,
        };

        test_read(&spec)
    }

    #[test]
    pub(crate) fn test_read_wide_mul64() {
        let spec = ReadSpec {
            bristol: wide_mul64,
            ngates: 28032,
            nwires: 28160,
            input_sizes: vec![64, 64],
            output_sizes: vec![64, 64],
            nxor: 19904,
            nand: 8128,
            ninv: 0,
            neq: 0,
            neqw: 0,
        };

        test_read(&spec)
    }

    // TODO(isweet): Add targeted `read` tests that cover `EQ` and `EQW` gates (not covered by Nigel circuits)

    /*

    // Tests for other Nigel circuits that are not (yet) included in `circuits`

    #[test]
    pub(crate) fn test_read_signed_div64() {
        let spec = ReadSpec {
            bristol: signed_div64,
            ngates: 29926,
            nwires: 30054,
            input_sizes: vec![64, 64],
            output_sizes: vec![64],
            nxor: 24817,
            nand: 4664,
            ninv: 445,
            neq: 0,
            neqw: 0,
        };

        test_read(&spec)
    }

    #[test]
    pub(crate) fn test_read_unsigned_div64() {
        let spec = ReadSpec {
            bristol: unsigned_div64,
            ngates: 16952,
            nwires: 17080,
            input_sizes: vec![64, 64],
            output_sizes: vec![64],
            nxor: 12603,
            nand: 4285,
            ninv: 64,
            neq: 0,
            neqw: 0,
        };

        test_read(&spec)
    }

    #[test]
    pub(crate) fn test_read_eq_zero64() {
        let spec = ReadSpec {
            bristol: eq_zero64,
            ngates: 127,
            nwires: 191,
            input_sizes: vec![64],
            output_sizes: vec![1],
            nxor: 0,
            nand: 63,
            ninv: 64,
            neq: 0,
            neqw: 0,
        };

        test_read(&spec)
    }

    #[test]
    pub(crate) fn test_read_aes128() {
        let spec = ReadSpec {
            bristol: aes_128,
            ngates: 36663,
            nwires: 36919,
            input_sizes: vec![128, 128],
            output_sizes: vec![128],
            nxor: 28176,
            nand: 6400,
            ninv: 2087,
            neq: 0,
            neqw: 0,
        };

        test_read(&spec)
    }

    #[test]
    pub(crate) fn test_read_aes192() {
        let spec = ReadSpec {
            bristol: aes_192,
            ngates: 41565,
            nwires: 41885,
            input_sizes: vec![192, 128],
            output_sizes: vec![128],
            nxor: 32080,
            nand: 7168,
            ninv: 2317,
            neq: 0,
            neqw: 0,
        };

        test_read(&spec)
    }

    #[test]
    pub(crate) fn test_read_aes256() {
        let spec = ReadSpec {
            bristol: aes_256,
            ngates: 50666,
            nwires: 51050,
            input_sizes: vec![256, 128],
            output_sizes: vec![128],
            nxor: 39008,
            nand: 8832,
            ninv: 2826,
            neq: 0,
            neqw: 0,
        };

        test_read(&spec)
    }

    #[test]
    pub(crate) fn test_read_keccak() {
        let spec = ReadSpec {
            bristol: keccak,
            ngates: 192086,
            nwires: 193686,
            input_sizes: vec![1600],
            output_sizes: vec![1600],
            nxor: 115200,
            nand: 38400,
            ninv: 38486,
            neq: 0,
            neqw: 0,
        };

        test_read(&spec)
    }

    #[test]
    pub(crate) fn test_read_sha256() {
        let spec = ReadSpec {
            bristol: sha_256,
            ngates: 135073,
            nwires: 135841,
            input_sizes: vec![512, 256],
            output_sizes: vec![256],
            nxor: 110644,
            nand: 22573,
            ninv: 1856,
            neq: 0,
            neqw: 0,
        };

        test_read(&spec)
    }

    #[test]
    pub(crate) fn test_read_sha512() {
        let spec = ReadSpec {
            bristol: sha_512,
            ngates: 349617,
            nwires: 351153,
            input_sizes: vec![1024, 512],
            output_sizes: vec![512],
            nxor: 286724,
            nand: 57947,
            ninv: 4946,
            neq: 0,
            neqw: 0,
        };

        test_read(&spec)
    }
     */
}
