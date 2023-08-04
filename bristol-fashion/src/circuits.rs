// TODO(isweet): Define cache according to Stuart's suggested macro, see https://gist.github.com/Isweet/22c598b7e9b19c84750f585319dddf7a

use crate::{read, Circuit};

use std::io::Cursor;

macro_rules! define_cached_circuit {
    ($name:ident, $loc:tt) => {
        thread_local! {
            static $name: Circuit = {
                let c = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/circuits/", $loc));
                let reader = Cursor::new(c);
                read(reader).unwrap()
            }
        }
    };
}

define_cached_circuit!(ADD64, "adder64.txt");

/// An owned copy of the optimized 64-bit adder circuit.
/// This circuit computes `a + b` where `a`, `b` and the result
/// `a + b` are all 64-bit integers in little endian.
///
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
#[inline(never)]
pub fn add64() -> Circuit {
    ADD64.with(Circuit::clone)
}

/// Apply a continuation to the optimized 64-bit adder circuit.
/// This circuit computes `a + b` where `a`, `b` and the result
/// `a + b` are all 64-bit integers in little endian.
///
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
#[inline(never)]
pub fn with_add64<F, R>(f: F) -> R
where
    F: FnOnce(&Circuit) -> R,
{
    ADD64.with(f)
}

define_cached_circuit!(SUB64, "sub64.txt");

/// An owned copy of the optimized 64-bit subtraction circuit.
/// This circuit computes `a - b` where `a`, `b`, and the result
/// `a - b` are all 64-bit integers in little endian.
///
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
#[inline(never)]
pub fn sub64() -> Circuit {
    SUB64.with(Circuit::clone)
}

/// Apply a continuation to the optimized 64-bit subtraction circuit.
/// This circuit computes `a - b` where `a`, `b`, and the result
/// `a - b` are all 64-bit integers in little endian.
///
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
#[inline(never)]
pub fn with_sub64<F, R>(f: F) -> R
where
    F: FnOnce(&Circuit) -> R,
{
    SUB64.with(f)
}

define_cached_circuit!(NEG64, "neg64.txt");

/// An owned copy of the optimized 64-bit negation circuit.
/// This circuit computes `-a` where `a` and the result
/// `-a` are both 64-bit integers in little endian.
///
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
#[inline(never)]
pub fn neg64() -> Circuit {
    NEG64.with(Circuit::clone)
}

/// Apply a continuation to the optimized 64-bit negation circuit.
/// This circuit computes `-a` where `a` and the result
/// `-a` are both 64-bit integers in little endian.
///
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
#[inline(never)]
pub fn with_neg64<F, R>(f: F) -> R
where
    F: FnOnce(&Circuit) -> R,
{
    NEG64.with(f)
}

define_cached_circuit!(MUL64, "mult64.txt");

/// An owned copy of the optimized 64-bit multiplication circuit.
/// This circuit computes `a * b` where `a`, `b`, and the result
/// `a * b` are all 64-bit integers in little endian.
///
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
#[inline(never)]
pub fn mul64() -> Circuit {
    MUL64.with(Circuit::clone)
}

/// Apply a continuation to the optimized 64-bit multiplication circuit.
/// This circuit computes `a * b` where `a`, `b`, and the result
/// `a * b` are all 64-bit integers in little endian.
///
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
#[inline(never)]
pub fn with_mul64<F, R>(f: F) -> R
where
    F: FnOnce(&Circuit) -> R,
{
    MUL64.with(f)
}

define_cached_circuit!(WIDE_MUL64, "mult2_64.txt");

/// An owned copy of the optimized 64-bit wide multiplication circuit.
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
#[inline(never)]
pub fn wide_mul64() -> Circuit {
    WIDE_MUL64.with(Circuit::clone)
}

/// Apply a continuation to the optimized 64-bit wide multiplication circuit.
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
#[inline(never)]
pub fn with_wide_mul64<F, R>(f: F) -> R
where
    F: FnOnce(&Circuit) -> R,
{
    WIDE_MUL64.with(f)
}
