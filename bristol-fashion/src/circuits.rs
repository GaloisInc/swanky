// TODO(isweet): Define cache according to Stuart's suggested macro, see https://gist.github.com/Isweet/22c598b7e9b19c84750f585319dddf7a

use crate::{read, Circuit};
use std::io::Cursor;

macro_rules! define_cached_circuit {
    ($name:ident, $loc:tt) => {
        thread_local! {
            pub static $name: Circuit = {
                let contents = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/circuits/", $loc));
                let reader = Cursor::new(contents);
                read(reader).unwrap()
            }
        }
    }
}

define_cached_circuit!(ADD64, "adder64.txt");

/// A cached copy of the optimized 64-bit adder circuit.
/// This circuit computes `a + b` where `a`, `b` and the result
/// `a + b` are all 64-bit integers in little endian.
///
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
#[macro_export]
macro_rules! add64 {
    () => {
        ADD64.with(Circuit::clone)
    };
}

define_cached_circuit!(SUB64, "sub64.txt");

/// A cached copy of the optimized 64-bit subtraction circuit.
/// This circuit computes `a - b` where `a`, `b`, and the result
/// `a - b` are all 64-bit integers in little endian.
///
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
#[macro_export]
macro_rules! sub64 {
    () => {
        SUB64.with(Circuit::clone)
    };
}

define_cached_circuit!(NEG64, "neg64.txt");

/// A cached copy of the optimized 64-bit negation circuit.
/// This circuit computes `-a` where `a` and the result
/// `-a` are both 64-bit integers in little endian.
///
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
#[macro_export]
macro_rules! neg64 {
    () => {
        NEG64.with(Circuit::clone)
    };
}

define_cached_circuit!(MUL64, "mult64.txt");

/// A cached copy of the optimized 64-bit multiplication circuit.
/// This circuit computes `a * b` where `a`, `b`, and the result
/// `a * b` are all 64-bit integers in little endian.
///
/// See: https://homes.esat.kuleuven.be/~nsmart/MPC/.
#[macro_export]
macro_rules! mul64 {
    () => {
        MUL64.with(Circuit::clone)
    };
}

define_cached_circuit!(WIDE_MUL64, "mult2_64.txt");

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
#[macro_export]
macro_rules! wide_mul64 {
    () => {
        WIDE_MUL64.with(Circuit::clone)
    };
}
