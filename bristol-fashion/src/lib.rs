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

#[derive(Copy, Clone)]
pub enum Gate {
    XOR { a: Wire, b: Wire, out: Wire },
    AND { a: Wire, b: Wire, out: Wire },
    INV { a: Wire, out: Wire },
    EQ  { lit: bool, out: Wire },
    EQW { a: Wire, out: Wire },
}

#[derive(Clone)]
pub struct Circuit {
    ngates: usize,
    nwires: usize,
    inputs: Vec<usize>,
    outputs: Vec<usize>,
    gates: Vec<Gate>,
}

impl Circuit {
    pub fn ngates(&self) -> usize {
        self.ngates
    }

    pub fn nwires(&self) -> usize {
        self.nwires
    }
    
    pub fn inputs(&self) -> Vec<usize> {
        self.inputs.clone()
    }
    
    pub fn outputs(&self) -> Vec<usize> {
        self.outputs.clone()
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

    fn read_ngates(tokens: &mut SplitWhitespace) -> Result<usize, Error> {
        Self::read_usize(tokens, "unexpected EOL, expected ngates")
    }

    pub fn read(&mut self) -> Result<Circuit, Error> {
        // Read number of gates (`ngates`) and number of wires (`nwires`) from first line
        let mut tokens = self.next_line()?.ok_or(ParseBristolError { inner: "unexpected EOF on line 1".to_string() })?;
        let ngates = Self::read_ngates(&mut tokens)?;
        let nwires = Self::read_usize(&mut tokens, "unexpected EOL, expected nwires")?;
        // TODO(isweet): Check EOL here

        // Read number of inputs and sizes from second line
        self.line.clear();
        self.reader.read_line(&mut self.line)?;
        let mut tokens = self.line.split_whitespace();
        let ninputs = tokens.next().unwrap().parse()?;
        assert_eq!(tokens.clone().count(), ninputs);
        let mut inputs = Vec::with_capacity(ninputs);
        for _ in 0..ninputs {
            let n = tokens.next().unwrap().parse()?;
            inputs.push(n);
        }

        // Read number of outputs and sizes from third line
        self.line.clear();
        self.reader.read_line(&mut self.line)?;
        let mut tokens = self.line.split_whitespace();
        let noutputs = tokens.next().unwrap().parse()?;
        assert_eq!(tokens.clone().count(), noutputs);
        let mut outputs = Vec::with_capacity(noutputs);
        for _ in 0..noutputs {
            let n = tokens.next().unwrap().parse()?;
            outputs.push(n);
        }
        
        // Skip an empty line
        self.line.clear();
        self.reader.read_line(&mut self.line)?;
        assert_eq!(self.line.split_whitespace().count(), 0);

        // Read gates from remaining lines
        let gates: Vec<Gate> = Vec::new();
        loop {
            self.line.clear();
            let n = self.reader.read_line(&mut self.line)?;
            if n == 0 {
                break;
            }
            let mut tokens = self.line.split_whitespace();
            let gate_kind = tokens.clone().last().unwrap(); // TODO(isweet): This should be a parse error
        }

        assert_eq!(gates.len(), ngates);
        
        
        Ok(Circuit {
            ngates,
            nwires,
            inputs,
            outputs,
            gates: todo!(),
        })
    }
}

// TODO(isweet): Can I do better than the below?
enum StdLib {
    Adder64,
    Sub64,
}

impl StdLib {
    fn name(&self) -> &str {
        match self {
            Adder64 => "adder64.txt",
            Sub64 => "sub64.txt",
        }
    }
}

thread_local! {
    static CACHE: [Option<Circuit>; 2] = {
        let mut ret = [None, None];
        
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits");

        let c = StdLib::Adder64;
        ret[c as usize] = Some(Reader::new(&path.join(c.name())).unwrap().read().unwrap());
        let c = StdLib::Sub64;
        ret[c as usize] = Some(Reader::new(&path.join(c.name())).unwrap().read().unwrap());

        ret
    }
}

fn fetch(c: StdLib) -> Circuit {
    CACHE.with(|cache| { cache[c as usize].as_ref().unwrap().clone() })
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
        inputs: Vec<usize>,
        outputs: Vec<usize>,
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
        assert_eq!(bristol.inputs(), spec.inputs);
        assert_eq!(bristol.outputs(), spec.outputs);
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
            inputs: vec![64, 64],
            outputs: vec![64],
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
            inputs: vec![64, 64],
            outputs: vec![64],
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
