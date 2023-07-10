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

const STDLIB: [StdLib; COUNT] = [
    StdLib::Add64,
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
