//! The `Fancy` trait represents the kinds of computations possible in `fancy-garbling`.
//!
//! An implementer must be able to create inputs, constants, do modular arithmetic, and
//! create projections.

use itertools::Itertools;

use crate::error::FancyError;

pub use crt::{Bundle, BundleGadgets};

mod crt;

/// An object that has some modulus. Basic object of `Fancy` computations.
pub trait HasModulus {
    /// The modulus of the wire.
    fn modulus(&self) -> u16;
}

/// The index of a thread for synchronization.
///
/// This is used within a thread to ensure all the messages within that thread are
/// sequential, and are delivered to the correct Evaluator thread.
// pub type SyncIndex = u8;

/// DSL for the basic computations supported by `fancy-garbling`.
pub trait Fancy {
    /// The underlying wire datatype created by an object implementing `Fancy`.
    type Item: Clone + HasModulus;

    /// Errors which may be thrown by the users of Fancy.
    type Error: std::fmt::Debug + std::fmt::Display + std::convert::From<FancyError>;

    /// Create an input for the garbler with modulus `q` and optional garbler-private value `x`.
    fn garbler_input(&self, q: u16, opt_x: Option<u16>) -> Result<Self::Item, Self::Error>;

    /// Create an input for the evaluator with modulus `q`.
    fn evaluator_input(&self, q: u16) -> Result<Self::Item, Self::Error>;

    /// Create a constant `x` with modulus `q`.
    fn constant(&self, x: u16, q: u16) -> Result<Self::Item, Self::Error>;

    /// Add `x` and `y`.
    fn add(&self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error>;

    /// Subtract `x` and `y`.
    fn sub(&self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error>;

    /// Multiply `x` times the constant `c`.
    fn cmul(&self, x: &Self::Item, c: u16) -> Result<Self::Item, Self::Error>;

    /// Multiply `x` and `y`.
    fn mul(&self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error>;

    /// Project `x` according to the truth table `tt`. Resulting wire has modulus `q`.
    ///
    /// Optional `tt` is useful for hiding the gate from evaluator.
    fn proj(&self, x: &Self::Item, q: u16, tt: Option<Vec<u16>>)
        -> Result<Self::Item, Self::Error>;

    /// Process this wire as output.
    fn output(&self, x: &Self::Item) -> Result<(), Self::Error>;

    ////////////////////////////////////////////////////////////////////////////////
    // synchronization

    /// Start synchronization of internal messages.
    ///
    /// Optional, throws `FancyError::NotImplemented` if used without an implementation.
    // fn begin_sync(&self, _num_indices: SyncIndex) -> Result<(), Self::Error> {
    //     Err(Self::Error::from(FancyError::NotImplemented))
    // }

    /// Declare this index to be done.
    ///
    /// Optional, throws `FancyError::NotImplemented` if used without an implementation.
    // fn finish_index(&self, _ix: SyncIndex) -> Result<(), Self::Error> {
    //     Err(Self::Error::from(FancyError::NotImplemented))
    // }

    ////////////////////////////////////////////////////////////////////////////////
    // Functions built on top of basic fancy operations.

    /// Create `n` garbler inputs with the moduli `qs` and optional inputs `xs`.
    fn garbler_inputs(
        &self,
        qs: &[u16],
        opt_xs: Option<Vec<u16>>,
    ) -> Result<Vec<Self::Item>, Self::Error> {
        let xs = to_vec_option(opt_xs, qs.len());
        qs.iter()
            .zip(xs)
            .map(|(&q, x)| self.garbler_input(q, x))
            .collect()
    }

    /// Create `n` evaluator inputs with the moduli `qs`.
    fn evaluator_inputs(&self, qs: &[u16]) -> Result<Vec<Self::Item>, Self::Error> {
        qs.iter().map(|&q| self.evaluator_input(q)).collect()
    }

    /// Sum up a slice of wires.
    fn add_many(&self, args: &[Self::Item]) -> Result<Self::Item, Self::Error> {
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

    /// Xor is just addition, with the requirement that `x` and `y` are mod 2.
    fn xor(&self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        if x.modulus() != 2 {
            return Err(Self::Error::from(FancyError::InvalidArgMod {
                got: x.modulus(),
                needed: 2,
            }));
        }
        if y.modulus() != 2 {
            return Err(Self::Error::from(FancyError::InvalidArgMod {
                got: y.modulus(),
                needed: 2,
            }));
        }
        self.add(x, y)
    }

    /// Negate by xoring `x` with `1`.
    fn negate(&self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        if x.modulus() != 2 {
            return Err(Self::Error::from(FancyError::InvalidArgMod {
                got: x.modulus(),
                needed: 2,
            }));
        }
        let one = self.constant(1, 2)?;
        self.xor(x, &one)
    }

    /// And is just multiplication, with the requirement that `x` and `y` are mod 2.
    fn and(&self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        if x.modulus() != 2 {
            return Err(Self::Error::from(FancyError::InvalidArgMod {
                got: x.modulus(),
                needed: 2,
            }));
        }
        if y.modulus() != 2 {
            return Err(Self::Error::from(FancyError::InvalidArgMod {
                got: y.modulus(),
                needed: 2,
            }));
        }
        self.mul(x, y)
    }

    /// Or uses Demorgan's Rule implemented with multiplication and negation.
    fn or(&self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        if x.modulus() != 2 {
            return Err(Self::Error::from(FancyError::InvalidArgMod {
                got: x.modulus(),
                needed: 2,
            }));
        }
        if y.modulus() != 2 {
            return Err(Self::Error::from(FancyError::InvalidArgMod {
                got: y.modulus(),
                needed: 2,
            }));
        }
        let notx = self.negate(x)?;
        let noty = self.negate(y)?;
        let z = self.and(&notx, &noty)?;
        self.negate(&z)
    }

    /// Returns 1 if all wires equal 1.
    fn and_many(&self, args: &[Self::Item]) -> Result<Self::Item, Self::Error> {
        if args.len() < 2 {
            return Err(Self::Error::from(FancyError::InvalidArgNum {
                got: args.len(),
                needed: 2,
            }));
        }
        args.iter()
            .skip(1)
            .fold(Ok(args[0].clone()), |acc, x| self.and(&(acc?), x))
    }

    /// Returns 1 if any wire equals 1.
    fn or_many(&self, args: &[Self::Item]) -> Result<Self::Item, Self::Error> {
        if args.len() < 2 {
            return Err(Self::Error::from(FancyError::InvalidArgNum {
                got: args.len(),
                needed: 2,
            }));
        }
        args.iter()
            .skip(1)
            .fold(Ok(args[0].clone()), |acc, x| self.or(&(acc?), x))
    }

    /// Change the modulus of `x` to `to_modulus` using a projection gate.
    fn mod_change(&self, x: &Self::Item, to_modulus: u16) -> Result<Self::Item, Self::Error> {
        let from_modulus = x.modulus();
        if from_modulus == to_modulus {
            return Ok(x.clone());
        }
        let tab = (0..from_modulus).map(|x| x % to_modulus).collect_vec();
        self.proj(x, to_modulus, Some(tab))
    }

    /// Binary adder. Returns the result and the carry.
    fn adder(
        &self,
        x: &Self::Item,
        y: &Self::Item,
        carry_in: Option<&Self::Item>,
    ) -> Result<(Self::Item, Self::Item), Self::Error> {
        if x.modulus() != 2 {
            return Err(Self::Error::from(FancyError::InvalidArgMod {
                got: x.modulus(),
                needed: 2,
            }));
        }
        if y.modulus() != 2 {
            return Err(Self::Error::from(FancyError::InvalidArgMod {
                got: y.modulus(),
                needed: 2,
            }));
        }
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

    /// If `b = 0` returns `x` else `y`.
    fn mux(
        &self,
        b: &Self::Item,
        x: &Self::Item,
        y: &Self::Item,
    ) -> Result<Self::Item, Self::Error> {
        let notb = self.negate(b)?;
        let xsel = self.and(&notb, x)?;
        let ysel = self.and(b, y)?;
        self.add(&xsel, &ysel)
    }

    /// If `x = 0` returns the constant `b1` else return `b2`. Folds constants if possible.
    fn mux_constant_bits(
        &self,
        x: &Self::Item,
        b1: bool,
        b2: bool,
    ) -> Result<Self::Item, Self::Error> {
        if x.modulus() != 2 {
            return Err(Self::Error::from(FancyError::InvalidArgMod {
                got: x.modulus(),
                needed: 2,
            }));
        }
        if !b1 && b2 {
            Ok(x.clone())
        } else if b1 && !b2 {
            self.negate(x)
        } else if !b1 && !b2 {
            self.constant(0, 2)
        } else {
            self.constant(1, 2)
        }
    }

    /// Output a slice of wires.
    fn outputs(&self, xs: &[Self::Item]) -> Result<(), Self::Error> {
        for x in xs.iter() {
            self.output(x)?;
        }
        Ok(())
    }
}

fn to_vec_option<T>(opt_xs: Option<Vec<T>>, len: usize) -> Vec<Option<T>> {
    opt_xs
        .map(|vals| {
            // transform option of slice into vec of options
            vals.into_iter().map(Some).collect()
        })
        .unwrap_or_else(|| (0..len).map(|_| None).collect())
}
