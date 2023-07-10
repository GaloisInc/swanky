//! This module implements a reader for "Bristol Fashion" circuit definition files.

use std::path::Path;
use std::path::PathBuf;
use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;
use std::str::SplitWhitespace;

#[derive(Debug)]
pub enum ParseError {
    ParseIntError(std::num::ParseIntError),
    ParseBristolError(String),    
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            ParseError::ParseIntError(e) => format!("Int: {e}"),            
            ParseError::ParseBristolError(e) => format!("Bristol: {e}"),
        })
    }
}

#[derive(Debug)]
pub enum Error {
    IOError(std::io::Error),
    ParseError(ParseError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Error::IOError(e) => format!("I/O Error: {e}"),
                Error::ParseError(e) => format!("Parse Error: {e}"),
            }
        )
    }    
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IOError(e)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Error::ParseError(ParseError::ParseIntError(e))
    }
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Error::ParseError(ParseError::ParseBristolError(e))
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

/// A Bristol Fashion circuit.
#[derive(Debug, Clone)]
pub struct Circuit {
    /// The number of gates in this circuit.    
    pub ngates: usize,
    /// The number of wires in this circuit.    
    pub nwires: usize,
    /// The sizes of each input to this circuit.
    /// For example, `vec![64, 64]` denotes a circuit with
    /// two inputs of `64` bits each.    
    pub input_sizes: Vec<usize>,
    /// The sizes of each output of this circuit.
    /// For example, `vec![64]` denotes a circuit with
    /// one output of `64` bits.    
    pub output_sizes: Vec<usize>,
    /// A topologically sorted list of gates.
    pub gates: Vec<Gate>,
}

impl Circuit {
    /// The number of XOR gates in this circuit.
    pub fn nxor(&self) -> usize {
        self.gates.iter().filter(|&g| match g {
            Gate::XOR { a: _, b: _, out: _ } => true,
            _ => false,
        }).count()
    }

    /// The number of AND gates in this circuit.
    pub fn nand(&self) -> usize {
        self.gates.iter().filter(|&g| match g {
            Gate::AND { a: _, b: _, out: _ } => true,
            _ => false,
        }).count()
    }

    /// The number of INV gates in this circuit.
    pub fn ninv(&self) -> usize {
        self.gates.iter().filter(|&g| match g {
            Gate::INV { a: _, out: _ } => true,
            _ => false,
        }).count()
    }

    /// The number of EQ gates in this circuit.
    pub fn neq(&self) -> usize {
        self.gates.iter().filter(|&g| match g {
            Gate::EQ { lit: _, out: _ } => true,
            _ => false,
        }).count()
    }

    /// The number of EQW gates in this circuit.
    pub fn neqw(&self) -> usize {
        self.gates.iter().filter(|&g| match g {
            Gate::EQW { a: _, out: _ } => true,
            _ => false,
        }).count()         
    }
}

/// A reader that constructs a Bristol Fashion `Circuit` from
/// a file path.
pub struct Reader {
    reader: BufReader<File>,
    line: String,
    row: usize,
}

impl Reader {
    /// Creates a new `Reader` from a path to a Bristol Fashion file.
    /// Produces an IO error if the file does not exist.
    pub fn new(path: &Path) -> Result<Reader, Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let line = String::new();        
        let row = 0;
        Ok(Self { reader, line, row })
    }

    fn next_line(&mut self) -> Result<Option<SplitWhitespace>, Error> {
        self.line.clear();
        let n = self.reader.read_line(&mut self.line)?;
        self.row += 1;        
        Ok(if n != 0 { Some(self.line.split_whitespace()) } else { None })
    }

    fn expect_line(&mut self) -> Result<SplitWhitespace, Error> {
        let row = self.row;        
        let ret = self.next_line()?;
        ret.ok_or(format!("unexpected EOF on line {}", row).into())
    }

    fn read_usize(tokens: &mut SplitWhitespace, msg: &str) -> Result<usize, Error> {
        let x = tokens.next().ok_or(msg.to_string())?.parse::<usize>()?;
        Ok(x)
    }

    fn read_bool(tokens: &mut SplitWhitespace, msg: &str) -> Result<bool, Error> {
        let x = tokens.next().ok_or(msg.to_string())?.parse::<u8>()?;
        (x == 0 || x == 1).then_some(()).ok_or(format!("expected 0 or 1, but got {}", x))?;
        Ok(if x == 0 { false } else { true })
    }

    fn read_gate_kind<'a>(tokens: &mut SplitWhitespace<'a>) -> Result<&'a str, Error> {
        let x = tokens.next_back().ok_or("unexpected EOL, expected gate kind".to_string())?;
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
        (in_arity == 2).then_some(()).ok_or(format!("unexpected input arity, expected 2 but got {}", in_arity))?;
        let out_arity = Self::read_gate_output_arity(tokens)?;
        (out_arity == 1).then_some(()).ok_or(format!("unexpected output arity, expected 1 but got {}", out_arity))?;
        let a = Self::read_gate_input(tokens)?;
        let b = Self::read_gate_input(tokens)?;
        let out = Self::read_gate_output(tokens)?;
        let _ = Self::read_eol(tokens)?;
        Ok((a, b, out))
    }

    fn read_unary_gate(tokens: &mut SplitWhitespace) -> Result<(Wire, Wire), Error> {
        let in_arity = Self::read_gate_input_arity(tokens)?;
        (in_arity == 1).then_some(()).ok_or(format!("unexpected input arity, expected 1 but got {}", in_arity))?;
        let out_arity = Self::read_gate_output_arity(tokens)?;
        (out_arity == 1).then_some(()).ok_or(format!("unexpected output arity, expected 1 but got {}", out_arity))?;
        let a = Self::read_gate_input(tokens)?;
        let out = Self::read_gate_output(tokens)?;
        let _ = Self::read_eol(tokens)?;
        Ok((a, out))
    }

    fn read_eq_gate(tokens: &mut SplitWhitespace) -> Result<(bool, Wire), Error> {
        let in_arity = Self::read_gate_input_arity(tokens)?;
        (in_arity == 1).then_some(()).ok_or(format!("unexpected input arity, expected 1 but got {}", in_arity))?;
        let out_arity = Self::read_gate_output_arity(tokens)?;
        (out_arity == 1).then_some(()).ok_or(format!("unexpected output arity, expected 1 but got {}", out_arity))?;
        let lit = Self::read_gate_input_lit(tokens)?;
        let out = Self::read_gate_output(tokens)?;
        let _ = Self::read_eol(tokens)?;
        Ok((lit, out))
    }

    fn read_eol(tokens: &mut SplitWhitespace) -> Result<(), Error> {
        let x = tokens.next();
        match x {
            Some(_) => Err(Error::ParseError(ParseError::ParseBristolError("unexpected token, expected EOL".to_string()))),
            None => Ok(()),
        }
    }

    /// Parses the underlying Bristol Fashion file into a `Circuit`.
    /// Produces a parse error if the file is not well-formed Bristol Fashion.
    pub fn read(&mut self) -> Result<Circuit, Error> {
        // Read number of gates (`ngates`) and number of wires (`nwires`) from first line
        let mut tokens = self.expect_line()?;
        let ngates = Self::read_ngates(&mut tokens)?;
        let nwires = Self::read_nwires(&mut tokens)?;
        let _ = Self::read_eol(&mut tokens)?;
        
        // Read number of inputs and sizes from second line
        let mut tokens = self.expect_line()?;
        let ninputs = Self::read_ninputs(&mut tokens)?;
        let mut input_sizes = Vec::with_capacity(ninputs);
        for _ in 0..ninputs {
            let input_size = Self::read_input_size(&mut tokens)?;
            input_sizes.push(input_size);
        }
        let _ = Self::read_eol(&mut tokens)?;

        // Read number of outputs and sizes from third line
        let mut tokens = self.expect_line()?;
        let noutputs = Self::read_noutputs(&mut tokens)?;
        let mut output_sizes = Vec::with_capacity(noutputs);
        for _ in 0..noutputs {
            let output_size = Self::read_output_size(&mut tokens)?;
            output_sizes.push(output_size);
        }
        let _ = Self::read_eol(&mut tokens)?;
        
        // Skip an empty line
        let mut tokens = self.expect_line()?;
        let _ = Self::read_eol(&mut tokens)?;

        // Read gates from remaining lines
        let mut gates: Vec<Gate> = Vec::with_capacity(ngates);
        for i in 0..ngates {
            let mut tokens = self.expect_line()?;
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
                    return Err(Error::ParseError(ParseError::ParseBristolError(format!("unexpected gate kind on line {}: {}", 5 + i, gate_kind))));
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

// TODO(isweet): Define cache according to Stuart's suggested macro, see https://gist.github.com/Isweet/22c598b7e9b19c84750f585319dddf7a

enum StdLib {
    Add64 = 0,
    Sub64 = 1,
    Neg64 = 2,
    Mul64 = 3,
    WideMul64 = 4,
    DivS64 = 5,
    DivU64 = 6,
    EqZ64 = 7,
    AES128 = 8,
    AES192 = 9,
    AES256 = 10,
    Keccak = 11,
    SHA256 = 12,
    SHA512 = 13,
}

const COUNT: usize = 14;

const STDLIB: [StdLib; COUNT] =
    [StdLib::Add64,
     StdLib::Sub64,
     StdLib::Neg64,
     StdLib::Mul64,
     StdLib::WideMul64,
     StdLib::DivS64,
     StdLib::DivU64,
     StdLib::EqZ64,
     StdLib::AES128,
     StdLib::AES192,
     StdLib::AES256,
     StdLib::Keccak,
     StdLib::SHA256,
     StdLib::SHA512,
    ];

impl StdLib {
    fn name(&self) -> &str {
        match self {
            StdLib::Add64 => "adder64.txt",
            StdLib::Sub64 => "sub64.txt",
            StdLib::Neg64 => "neg64.txt",
            StdLib::Mul64 => "mult64.txt",
            StdLib::WideMul64 => "mult2_64.txt",
            StdLib::DivS64 => "divide64.txt",
            StdLib::DivU64 => "udivide64.txt",
            StdLib::EqZ64 => "zero_equal.txt",
            StdLib::AES128 => "aes_128.txt",
            StdLib::AES192 => "aes_192.txt",
            StdLib::AES256 => "aes_256.txt",
            StdLib::Keccak => "Keccak_f.txt",
            StdLib::SHA256 => "sha256.txt",
            StdLib::SHA512 => "sha512.txt",
        }
    }
}

thread_local! {
    static CACHE: [Circuit; COUNT] = {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits");
        STDLIB.map(|c| Reader::new(&path.join(c.name())).unwrap().read().unwrap())
    }
}

fn fetch(c: StdLib) -> Circuit {
    CACHE.with(|cache| { cache[c as usize].clone() })
}

/// A cached copy of the optimized 64-bit adder circuit.
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn add64() -> Circuit {
    fetch(StdLib::Add64)
}

/// A cached copy of the optimized 64-bit subtraction circuit.
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn sub64() -> Circuit {
    fetch(StdLib::Sub64)
}

/// A cached copy of the optimized 64-bit subtraction circuit.
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn neg64() -> Circuit {
    fetch(StdLib::Neg64)
}

/// A cached copy of the optimized 64-bit multiplication circuit.
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn mul64() -> Circuit {
    fetch(StdLib::Mul64)
}

/// A cached copy of the optimized 64-bit wide multiplication circuit.
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn wide_mul64() -> Circuit {
    fetch(StdLib::WideMul64)
}

/// A cached copy of the optimized 64-bit signed division circuit.
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn signed_div64() -> Circuit {
    fetch(StdLib::DivS64)
}

/// A cached copy of the optimized 64-bit unsigned division circuit.
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn unsigned_div64() -> Circuit {
    fetch(StdLib::DivU64)
}

/// A cached copy of the optimized 64-bit zero equality circuit.
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn eq_zero64() -> Circuit {
    fetch(StdLib::EqZ64)
}

/// A cached copy of the optimized AES-128 circuit.
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn aes_128() -> Circuit {
    fetch(StdLib::AES128)
}

/// A cached copy of the optimized AES-192 circuit.
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn aes_192() -> Circuit {
    fetch(StdLib::AES192)
}

/// A cached copy of the optimized AES-256 circuit.
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn aes_256() -> Circuit {
    fetch(StdLib::AES256)
}

/// A cached copy of the optimized Keccak circuit.
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn keccak() -> Circuit {
    fetch(StdLib::Keccak)
}

/// A cached copy of the optimized SHA-256 circuit.
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn sha_256() -> Circuit {
    fetch(StdLib::SHA256)
}

/// A cached copy of the optimized SHA-512 circuit.
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn sha_512() -> Circuit {
    fetch(StdLib::SHA512)
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
    pub (crate) fn test_read_add64() {
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

    #[test]
    pub (crate) fn test_read_neg64() {
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
    pub (crate) fn test_read_mul64() {
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
    pub (crate) fn test_read_wide_mul64() {
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

    #[test]
    pub (crate) fn test_read_signed_div64() {
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
    pub (crate) fn test_read_unsigned_div64() {
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
    pub (crate) fn test_read_eq_zero64() {
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
    pub (crate) fn test_read_aes128() {
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
    pub (crate) fn test_read_aes192() {
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
    pub (crate) fn test_read_aes256() {
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
    pub (crate) fn test_read_keccak() {
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
    pub (crate) fn test_read_sha256() {
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
    pub (crate) fn test_read_sha512() {
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

    // TODO(isweet): Add targeted `read` tests that cover `EQ` and `EQW` gates (not covered by Nigel circuits)
}
