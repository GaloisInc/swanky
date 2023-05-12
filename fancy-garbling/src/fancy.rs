//! The `Fancy` trait represents the kinds of computations possible in `fancy-garbling`.
//!
//! An implementer must be able to create inputs, constants, do modular arithmetic, and
//! create projections.

use crate::errors::FancyError;
use itertools::Itertools;

mod binary;
mod bundle;
mod crt;
mod input;
mod pmr;
mod reveal;
pub use binary::{BinaryBundle, BinaryGadgets};
pub use bundle::{ArithmeticBundleGadgets, BinaryBundleGadgets, Bundle, BundleGadgets};
pub use crt::{CrtBundle, CrtGadgets};
pub use input::FancyInput;
pub use reveal::FancyReveal;

/// An object that has some modulus. Basic object of `Fancy` computations.
pub trait HasModulus {
    /// The modulus of the wire.
    fn modulus(&self) -> u16;
}

/// Fancy DSL providing binary operations
///
pub trait FancyBinary: Fancy {
    /// Binary Xor
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error>;

    /// Binary And
    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error>;

    /// Binary Not
    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error>;

    /// Uses Demorgan's Rule implemented with an and gate and negation.
    fn or(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        let notx = self.negate(x)?;
        let noty = self.negate(y)?;
        let z = self.and(&notx, &noty)?;
        self.negate(&z)
    }

    /// Binary adder. Returns the result and the carry.
    fn adder(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        carry_in: Option<&Self::Item>,
    ) -> Result<(Self::Item, Self::Item), Self::Error> {
        if let Some(c) = carry_in {
            let z1 = self.xor(x, y)?;
            let z2 = self.xor(&z1, c)?;
            let z3 = self.xor(x, c)?;
            let z4 = self.and(&z1, &z3)?;
            let carry = self.xor(&z4, x)?;
            Ok((z2, carry))
        } else {
            let z = self.xor(x, y)?;
            let carry = self.and(x, y)?;
            Ok((z, carry))
        }
    }
    /// Returns 1 if all wires equal 1.
    fn and_many(&mut self, args: &[Self::Item]) -> Result<Self::Item, Self::Error> {
        if args.is_empty() {
            return Err(Self::Error::from(FancyError::InvalidArgNum {
                got: args.len(),
                needed: 1,
            }));
        }
        args.iter()
            .skip(1)
            .fold(Ok(args[0].clone()), |acc, x| self.and(&(acc?), x))
    }

    /// Returns 1 if any wire equals 1.
    fn or_many(&mut self, args: &[Self::Item]) -> Result<Self::Item, Self::Error> {
        if args.is_empty() {
            return Err(Self::Error::from(FancyError::InvalidArgNum {
                got: args.len(),
                needed: 1,
            }));
        }
        args.iter()
            .skip(1)
            .fold(Ok(args[0].clone()), |acc, x| self.or(&(acc?), x))
    }

    /// XOR many wires together
    fn xor_many(&mut self, args: &[Self::Item]) -> Result<Self::Item, Self::Error> {
        if args.len() < 2 {
            return Err(Self::Error::from(FancyError::InvalidArgNum {
                got: args.len(),
                needed: 2,
            }));
        }
        args.iter()
            .skip(1)
            .fold(Ok(args[0].clone()), |acc, x| self.xor(&(acc?), x))
    }

    /// If `x = 0` returns the constant `b1` else return `b2`. Folds constants if possible.
    fn mux_constant_bits(
        &mut self,
        x: &Self::Item,
        b1: bool,
        b2: bool,
    ) -> Result<Self::Item, Self::Error> {
        match (b1, b2) {
            (false, true) => Ok(x.clone()),
            (true, false) => self.negate(x),
            (false, false) => self.constant(0, 2),
            (true, true) => self.constant(1, 2),
        }
    }

    /// If `b = 0` returns `x` else `y`.
    fn mux(
        &mut self,
        b: &Self::Item,
        x: &Self::Item,
        y: &Self::Item,
    ) -> Result<Self::Item, Self::Error> {
        let notb = self.negate(b)?;
        let xsel = self.and(&notb, x)?;
        let ysel = self.and(b, y)?;
        self.xor(&xsel, &ysel)
    }
}

/// DSL for the basic computations supported by `fancy-garbling`.
///
/// Primarily used as a supertrait for `FancyBinary` and `FancyArithmetic`,
/// which indicate computation supported by the DSL.
pub trait Fancy {
    /// The underlying wire datatype created by an object implementing `Fancy`.
    type Item: Clone + HasModulus;

    /// Errors which may be thrown by the users of Fancy.
    type Error: std::fmt::Debug + std::fmt::Display + std::convert::From<FancyError>;

    /// Create a constant `x` with modulus `q`.
    fn constant(&mut self, x: u16, q: u16) -> Result<Self::Item, Self::Error>;

    /// Process this wire as output. Some `Fancy` implementers don't actually *return*
    /// output, but they need to be involved in the process, so they can return `None`.
    fn output(&mut self, x: &Self::Item) -> Result<Option<u16>, Self::Error>;

    /// Output a slice of wires.
    fn outputs(&mut self, xs: &[Self::Item]) -> Result<Option<Vec<u16>>, Self::Error> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            zs.push(self.output(x)?);
        }
        Ok(zs.into_iter().collect())
    }
}

/// DSL for arithmetic computation.
pub trait FancyArithmetic: Fancy {
    /// Add `x` and `y`.
    fn add(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error>;

    /// Subtract `x` and `y`.
    fn sub(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error>;

    /// Multiply `x` times the constant `c`.
    fn cmul(&mut self, x: &Self::Item, c: u16) -> Result<Self::Item, Self::Error>;

    /// Multiply `x` and `y`.
    fn mul(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error>;

    /// Project `x` according to the truth table `tt`. Resulting wire has modulus `q`.
    ///
    /// Optional `tt` is useful for hiding the gate from the evaluator.
    fn proj(
        &mut self,
        x: &Self::Item,
        q: u16,
        tt: Option<Vec<u16>>,
    ) -> Result<Self::Item, Self::Error>;

    ////////////////////////////////////////////////////////////////////////////////
    // Functions built on top of arithmetic fancy operations.

    /// Sum up a slice of wires.
    fn add_many(&mut self, args: &[Self::Item]) -> Result<Self::Item, Self::Error> {
        if args.len() < 2 {
            return Err(Self::Error::from(FancyError::InvalidArgNum {
                got: args.len(),
                needed: 2,
            }));
        }
        let mut z = args[0].clone();
        for x in args.iter().skip(1) {
            z = self.add(&z, x)?;
        }
        Ok(z)
    }
    /// Change the modulus of `x` to `to_modulus` using a projection gate.
    fn mod_change(&mut self, x: &Self::Item, to_modulus: u16) -> Result<Self::Item, Self::Error> {
        let from_modulus = x.modulus();
        if from_modulus == to_modulus {
            return Ok(x.clone());
        }
        let tab = (0..from_modulus).map(|x| x % to_modulus).collect_vec();
        self.proj(x, to_modulus, Some(tab))
    }
}

macro_rules! check_binary {
    ($x:ident) => {
        if $x.modulus() != 2 {
            return Err(Self::Error::from(FancyError::InvalidArgMod {
                got: $x.modulus(),
                needed: 2,
            }));
        }
    };
}

/// Given an `FancyArithmetic` implementation, it is always possible to derive
/// the operations required for `FancyBinary` by using the given arithmetic gadgets.
///
/// In this macro, `xor` and `and` use `add` and `mul` respectively as a subroutine,
/// while `negate` xors the wire with a constant.
/// Additionally, the modulus of each input wire is checked to make sure it is equal to 2.
/// Note, that there are frequently better ways to implement some of these operations (e.g. negate
/// in GC can often be written without requiring any communication).
/// However, this is not always relevant, such as when implementing the `Fancy` DSLs for `Dummy`.
///
/// Right now the macro can handle X or X<Y,...> mainly because I used it for `CircuitBuilder<ArithmeticCircuit>`
macro_rules! derive_binary {
    ($f:ident$(<$( $t:tt ),+>)?) => {
        impl FancyBinary for $f$(< $($t),* >)? {
            fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
                check_binary!(x);
                check_binary!(y);

                self.add(x, y)
            }

            fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
                check_binary!(x);
                check_binary!(y);

                self.mul(x, y)
            }

            fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
                check_binary!(x);

                let c = self.constant(1, 2)?;
                self.xor(x, &c)
            }
        }
    };
}
pub(crate) use check_binary;
pub(crate) use derive_binary;
