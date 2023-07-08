//! This module implements a parser for "Bristol Fashion" circuit definition files.

// Tasks:
// 1. Define the API
//   * Errors
//   * Debugging / Tracing
//   * Circuit Structure
//   * Circuit Builder
// 2. Define tests (steal / adapt from Alex's code)
// 3. Implement the API
//   * Use `BufRead::lines` and `str::split_whitespace`

// Reminders:
// 1. Don't worry about time / space
// 2. Don't use `nom` or any other fancy libraries
// 3. Don't bother splitting lexing / parsing or doing recursive descent
// 4. Don't represent any structure except exactly Bristol Fashion (e.g. no wire mapping)
// 5. This is due 9am EST Monday, Jul 10
//   * Successful completion requires...
//     (a) All tests pass
//     (b) Basic documentation on API
//     (c) MR submitted for review

use std::path::Path;
use std::path::PathBuf;
use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;
use std::str::SplitWhitespace;

#[derive(Debug)]
struct ParseBristolError {
    inner: String,
}

impl std::fmt::Display for ParseBristolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }    
}

#[derive(Debug)]
enum Error {
    IOError(std::io::Error),
    ParseBristolError(ParseBristolError),
    ParseIntError(std::num::ParseIntError),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IOError(e)
    }
}

impl From<ParseBristolError> for Error {
    fn from(e: ParseBristolError) -> Self {
        Error::ParseBristolError(e)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Error::ParseIntError(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Error::IOError(e) => format!("I/O error: {e}"),
                Error::ParseBristolError(e) => format!("Parse error: {e}"),
                Error::ParseIntError(e) => format!("Parse error: {e}"),
            }
        )
    }    
}

pub type Wire = usize;

#[derive(Debug, Copy, Clone)]
pub enum Gate {
    XOR { a: Wire, b: Wire, out: Wire },
    AND { a: Wire, b: Wire, out: Wire },
    INV { a: Wire, out: Wire },
    EQ  { lit: bool, out: Wire },
    EQW { a: Wire, out: Wire },
}

#[derive(Debug, Clone)]
pub struct Circuit {
    ngates: usize,
    nwires: usize,
    input_sizes: Vec<usize>,
    output_sizes: Vec<usize>,
    gates: Vec<Gate>,
}

impl Circuit {
    pub fn ngates(&self) -> usize {
        self.ngates
    }

    pub fn nwires(&self) -> usize {
        self.nwires
    }
    
    pub fn input_sizes(&self) -> Vec<usize> {
        self.input_sizes.clone()
    }
    
    pub fn output_sizes(&self) -> Vec<usize> {
        self.output_sizes.clone()
    }

    pub fn nxor(&self) -> usize {
        self.gates.iter().filter(|&g| match g {
            Gate::XOR { a: _, b: _, out: _ } => true,
            _ => false,
        }).count()
    }

    pub fn nand(&self) -> usize {
        self.gates.iter().filter(|&g| match g {
            Gate::AND { a: _, b: _, out: _ } => true,
            _ => false,
        }).count()
    }

    pub fn ninv(&self) -> usize {
        self.gates.iter().filter(|&g| match g {
            Gate::INV { a: _, out: _ } => true,
            _ => false,
        }).count()
    }

    pub fn neq(&self) -> usize {
        self.gates.iter().filter(|&g| match g {
            Gate::EQ { lit: _, out: _ } => true,
            _ => false,
        }).count()
    }

    pub fn neqw(&self) -> usize {
        self.gates.iter().filter(|&g| match g {
            Gate::EQW { a: _, out: _ } => true,
            _ => false,
        }).count()         
    }
}

struct Reader {
    reader: BufReader<File>,
    line: String,
}

impl Reader {
    pub fn new(path: &Path) -> Result<Reader, Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let line = String::new();
        Ok(Self { reader, line })
    }

    fn next_line(&mut self) -> Result<Option<SplitWhitespace>, Error> {
        self.line.clear();
        let n = self.reader.read_line(&mut self.line)?;
        Ok(if n != 0 { Some(self.line.split_whitespace()) } else { None })
    }

    fn read_usize(tokens: &mut SplitWhitespace, msg: &str) -> Result<usize, Error> {
        let x = tokens.next().ok_or(ParseBristolError { inner: msg.to_string() })?.parse::<usize>()?;
        Ok(x)
    }

    fn read_bool(tokens: &mut SplitWhitespace, msg: &str) -> Result<bool, Error> {
        let x = tokens.next().ok_or(ParseBristolError { inner: msg.to_string() })?.parse::<u8>()?;
        (x == 0 || x == 1).then_some(()).ok_or(ParseBristolError { inner: format!("expected 0 or 1, but got {}", x) })?;
        Ok(if x == 0 { false } else { true })
    }

    fn read_gate_kind<'a>(tokens: &mut SplitWhitespace<'a>) -> Result<&'a str, Error> {
        let x = tokens.next_back().ok_or(ParseBristolError { inner: "unexpected EOL, expected gate kind".to_string() })?;
        Ok(x)
    }

    fn read_ngates(tokens: &mut SplitWhitespace) -> Result<usize, Error> {
        Self::read_usize(tokens, "unexpected EOL, expected ngates")
    }

    fn read_nwires(tokens: &mut SplitWhitespace) -> Result<usize, Error> {
        Self::read_usize(tokens, "unexpected EOL, expected nwires")
    }

    fn read_ninputs(tokens: &mut SplitWhitespace) -> Result<usize, Error> {
        Self::read_usize(tokens, "unexpected EOL, expected ninputs")
    }

    fn read_input_size(tokens: &mut SplitWhitespace) -> Result<usize, Error> {
        Self::read_usize(tokens, "unexpected EOL, expected input size")
    }

    fn read_noutputs(tokens: &mut SplitWhitespace) -> Result<usize, Error> {
        Self::read_usize(tokens, "unexpected EOL, expected noutputs")
    }

    fn read_output_size(tokens: &mut SplitWhitespace) -> Result<usize, Error> {
        Self::read_usize(tokens, "unexpected EOL, expected output size")
    }

    fn read_gate_input_arity(tokens: &mut SplitWhitespace) -> Result<usize, Error> {
        Self::read_usize(tokens, "unexpected EOL, expected gate input arity")
    }

    fn read_gate_output_arity(tokens: &mut SplitWhitespace) -> Result<usize, Error> {
        Self::read_usize(tokens, "unexpected EOL, expected gate output arity")
    }

    fn read_gate_input(tokens: &mut SplitWhitespace) -> Result<usize, Error> {
        Self::read_usize(tokens, "unexpected EOL, expected gate input")
    }

    fn read_gate_input_lit(tokens: &mut SplitWhitespace) -> Result<bool, Error> {
        Self::read_bool(tokens, "unexpected EOL, expected gate input lit")
    }

    fn read_gate_output(tokens: &mut SplitWhitespace) -> Result<usize, Error> {
        Self::read_usize(tokens, "unexpected EOL, expected gate output")
    }

    fn read_binary_gate(tokens: &mut SplitWhitespace) -> Result<(Wire, Wire, Wire), Error> {
        let in_arity = Self::read_gate_input_arity(tokens)?;
        (in_arity == 2).then_some(()).ok_or(ParseBristolError { inner: format!("unexpected input arity, expected 2 but got {}", in_arity) })?;
        let out_arity = Self::read_gate_output_arity(tokens)?;
        (out_arity == 1).then_some(()).ok_or(ParseBristolError { inner: format!("unexpected output arity, expected 1 but got {}", out_arity) })?;
        let a = Self::read_gate_input(tokens)?;
        let b = Self::read_gate_input(tokens)?;
        let out = Self::read_gate_output(tokens)?;
        let _ = Self::read_eol(tokens)?;
        Ok((a, b, out))
    }

    fn read_unary_gate(tokens: &mut SplitWhitespace) -> Result<(Wire, Wire), Error> {
        let in_arity = Self::read_gate_input_arity(tokens)?;
        (in_arity == 1).then_some(()).ok_or(ParseBristolError { inner: format!("unexpected input arity, expected 1 but got {}", in_arity) })?;
        let out_arity = Self::read_gate_output_arity(tokens)?;
        (out_arity == 1).then_some(()).ok_or(ParseBristolError { inner: format!("unexpected output arity, expected 1 but got {}", out_arity) })?;
        let a = Self::read_gate_input(tokens)?;
        let out = Self::read_gate_output(tokens)?;
        let _ = Self::read_eol(tokens)?;
        Ok((a, out))
    }

    fn read_eq_gate(tokens: &mut SplitWhitespace) -> Result<(bool, Wire), Error> {
        let in_arity = Self::read_gate_input_arity(tokens)?;
        (in_arity == 1).then_some(()).ok_or(ParseBristolError { inner: format!("unexpected input arity, expected 1 but got {}", in_arity) })?;
        let out_arity = Self::read_gate_output_arity(tokens)?;
        (out_arity == 1).then_some(()).ok_or(ParseBristolError { inner: format!("unexpected output arity, expected 1 but got {}", out_arity) })?;
        let lit = Self::read_gate_input_lit(tokens)?;
        let out = Self::read_gate_output(tokens)?;
        let _ = Self::read_eol(tokens)?;
        Ok((lit, out))
    }

    fn read_eol(tokens: &mut SplitWhitespace) -> Result<(), Error> {
        let x = tokens.next();
        match x {
            Some(_) => Err(Error::ParseBristolError(ParseBristolError { inner: "unexpected token, expected EOL".to_string() })),
            None => Ok(()),
        }
    }

    pub fn read(&mut self) -> Result<Circuit, Error> {
        // Read number of gates (`ngates`) and number of wires (`nwires`) from first line
        let mut tokens = self.next_line()?.ok_or(ParseBristolError { inner: "unexpected EOF on line 1".to_string() })?;
        let ngates = Self::read_ngates(&mut tokens)?;
        let nwires = Self::read_nwires(&mut tokens)?;
        let _ = Self::read_eol(&mut tokens)?;
        
        // Read number of inputs and sizes from second line
        let mut tokens = self.next_line()?.ok_or(ParseBristolError { inner: "unexpected EOF on line 2".to_string() })?;
        let ninputs = Self::read_ninputs(&mut tokens)?;
        let mut input_sizes = Vec::with_capacity(ninputs);
        for _ in 0..ninputs {
            let input_size = Self::read_input_size(&mut tokens)?;
            input_sizes.push(input_size);
        }
        let _ = Self::read_eol(&mut tokens)?;

        // Read number of outputs and sizes from third line
        let mut tokens = self.next_line()?.ok_or(ParseBristolError { inner: "unexpected EOF on line 3".to_string() })?;
        let noutputs = Self::read_noutputs(&mut tokens)?;
        let mut output_sizes = Vec::with_capacity(noutputs);
        for _ in 0..noutputs {
            let output_size = Self::read_output_size(&mut tokens)?;
            output_sizes.push(output_size);
        }
        let _ = Self::read_eol(&mut tokens)?;
        
        // Skip an empty line
        let mut tokens = self.next_line()?.ok_or(ParseBristolError { inner: "unexpected EOF on line 4".to_string() })?;
        let _ = Self::read_eol(&mut tokens)?;

        // Read gates from remaining lines
        let mut gates: Vec<Gate> = Vec::new();
        for i in 0..ngates {
            let mut tokens = self.next_line()?.ok_or(ParseBristolError { inner: format!("unexpected EOF on line {}", 5 + i) })?;
            let gate_kind = Self::read_gate_kind(&mut tokens)?;
            match gate_kind {
                "XOR" => {
                    let (a, b, out) = Self::read_binary_gate(&mut tokens)?;
                    gates.push(Gate::XOR { a, b, out });
                },
                "AND" => {
                    let (a, b, out) = Self::read_binary_gate(&mut tokens)?;
                    gates.push(Gate::AND { a, b, out });
                },
                "INV" => {
                    let (a, out) = Self::read_unary_gate(&mut tokens)?;
                    gates.push(Gate::INV { a, out });
                },
                "EQW" => {
                    let (a, out) = Self::read_unary_gate(&mut tokens)?;
                    gates.push(Gate::EQW { a, out });
                },
                "EQ" => {
                    let (lit, out) = Self::read_eq_gate(&mut tokens)?;
                    gates.push(Gate::EQ { lit, out });
                },
                "MAND" => {
                    unimplemented!()
                },
                _ => {
                    return Err(Error::ParseBristolError(ParseBristolError { inner: format!("unexpected gate kind on line {}: {}", 5 + i, gate_kind) }));
                }
            }
        }

        // Skip trailing empty lines, but make sure they are empty
        loop {
            let tokens = self.next_line()?;
            match tokens {
                None => { break; },
                Some(mut tokens) => {
                    let _ = Self::read_eol(&mut tokens)?;
                },
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

// TODO(isweet): Can I do better than the below?
//   Yes, see: https://gist.github.com/Isweet/22c598b7e9b19c84750f585319dddf7a

enum StdLib {
    Adder64 = 0,
    Sub64 = 1,
}

const STDLIB: [StdLib; 2] = [StdLib::Adder64, StdLib::Sub64];

impl StdLib {
    fn name(&self) -> &str {
        match self {
            StdLib::Adder64 => "adder64.txt",
            StdLib::Sub64 => "sub64.txt",
        }
    }
}

thread_local! {
    static CACHE: [Circuit; 2] = {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits");
        STDLIB.map(|c| Reader::new(&path.join(c.name())).unwrap().read().unwrap())
    }
}

fn fetch(c: StdLib) -> Circuit {
    CACHE.with(|cache| { cache[c as usize].clone() })
}

pub fn adder64() -> Circuit {
    fetch(StdLib::Adder64)
}

pub fn sub64() -> Circuit {
    fetch(StdLib::Sub64)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ReadSpec {
        bristol: fn() -> Circuit,
        ngates: usize,
        nwires: usize,
        input_sizes: Vec<usize>,
        output_sizes: Vec<usize>,
        nxor: usize,
        nand: usize,
        ninv: usize,
        neq: usize,
        neqw: usize,
    }

    fn test_read(spec: &ReadSpec) {
        let bristol = (spec.bristol)();
        assert_eq!(bristol.ngates(), spec.ngates);
        assert_eq!(bristol.nwires(), spec.nwires);
        assert_eq!(bristol.input_sizes(), spec.input_sizes);
        assert_eq!(bristol.output_sizes(), spec.output_sizes);
        assert_eq!(bristol.nxor(), spec.nxor);
        assert_eq!(bristol.nand(), spec.nand);
        assert_eq!(bristol.ninv(), spec.ninv);
        assert_eq!(bristol.neq(), spec.neq);
        assert_eq!(bristol.neqw(), spec.neqw);
    }

    #[test]
    pub (crate) fn test_read_adder64() {
        let spec = ReadSpec {
            bristol: adder64,
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
    pub (crate) fn test_read_sub64() {
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

    // TODO: Additional testing...
    //  * Add `read` tests for remaining standard library (`mult64`, ...)
    //  * Add evaluation tests, since the `read` tests only check the number of gates (not structure)
}
