// TODO(isweet): Define cache according to Stuart's suggested macro, see https://gist.github.com/Isweet/22c598b7e9b19c84750f585319dddf7a

use crate::{Circuit, Reader};

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

enum StdLib {
    Add64 = 0,
    Sub64 = 1,
    Neg64 = 2,
    Mul64 = 3,
    WideMul64 = 4,
}

const COUNT: usize = 5;

const STDLIB: [StdLib; COUNT] = [
    StdLib::Add64,
    StdLib::Sub64,
    StdLib::Neg64,
    StdLib::Mul64,
    StdLib::WideMul64,
];

impl StdLib {
    fn name(&self) -> &str {
        match self {
            StdLib::Add64 => "adder64.txt",
            StdLib::Sub64 => "sub64.txt",
            StdLib::Neg64 => "neg64.txt",
            StdLib::Mul64 => "mult64.txt",
            StdLib::WideMul64 => "mult2_64.txt",
        }
    }
}

thread_local! {
    static CACHE: [Circuit; COUNT] = {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits");
        STDLIB.map(|c| {
            let file = File::open(path.join(c.name())).unwrap();
            let reader = BufReader::new(file);
            Reader::new(reader).read().unwrap()
        })
    }
}

fn fetch(c: StdLib) -> Circuit {
    CACHE.with(|cache| cache[c as usize].clone())
}

/// A cached copy of the optimized 64-bit adder circuit.
/// This circuit computes `a + b` where `a`, `b` and the result
/// `a + b` are all 64-bit integers in little endian.
///
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn add64() -> Circuit {
    fetch(StdLib::Add64)
}

/// A cached copy of the optimized 64-bit subtraction circuit.
/// This circuit computes `a - b` where `a`, `b`, and the result
/// `a - b` are all 64-bit integers in little endian.
///
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn sub64() -> Circuit {
    fetch(StdLib::Sub64)
}

/// A cached copy of the optimized 64-bit negation circuit.
/// This circuit computes `-a` where `a` and the result
/// `-a` are both 64-bit integers in little endian.
///
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn neg64() -> Circuit {
    fetch(StdLib::Neg64)
}

/// A cached copy of the optimized 64-bit multiplication circuit.
/// This circuit computes `a * b` where `a`, `b`, and the result
/// `a * b` are all 64-bit integers in little endian.
///
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn mul64() -> Circuit {
    fetch(StdLib::Mul64)
}

/// A cached copy of the optimized 64-bit wide multiplication circuit.
/// This circuit computes `a * b` where `a` and `b` are 64-bit integers
/// in little endian, and the result `a * b` is a 128-bit integer also
/// in little endian.
///
/// Note: Technically, the output of this circuit is split into
/// two 64-bit outputs, but this can be treated as a single 128-bit
/// output since the output wires of a Bristol Fashion circuit are
/// contiguous.
///
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
pub fn wide_mul64() -> Circuit {
    fetch(StdLib::WideMul64)
}
