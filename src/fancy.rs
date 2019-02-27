//! The `Fancy` trait represents the kinds of computations possible in `fancy-garbling`.
//!
//! An implementer must be able to create inputs, constants, do modular arithmetic, and
//! create projections.

use itertools::Itertools;

use crate::error::FancyError;
use crate::util;

/// An object that has some modulus. Basic object of Fancy compuations.
pub trait HasModulus {
    /// The modulus of the wire.
    fn modulus(&self) -> u16;
}

/// The index of a thread for synchronization.
///
/// This is used within a thread to ensure all the messages within that thread are
/// sequential, and are delivered to the correct Evaluator thread.
pub type SyncIndex = u8;

/// A collection of wires, useful for the garbled gadgets defined by `BundleGadgets`.
#[derive(Clone)]
pub struct Bundle<W: Clone + HasModulus>(Vec<W>);

impl<W: Clone + HasModulus> Bundle<W> {
    /// Create a new bundle from some wires.
    pub fn new(ws: Vec<W>) -> Bundle<W> {
        Bundle(ws)
    }

    /// Return the moduli of all the wires in the bundle.
    pub fn moduli(&self) -> Vec<u16> {
        self.0.iter().map(|w| w.modulus()).collect()
    }

    /// Extract the wires from this bundle.
    pub fn wires(&self) -> &[W] {
        &self.0
    }

    /// Get the number of wires in this bundle.
    pub fn size(&self) -> usize {
        self.0.len()
    }

    /// Whether this bundle only contains residues in mod 2.
    pub fn is_binary(&self) -> bool {
        self.moduli().iter().all(|m| *m == 2)
    }

    /// Returns a new bundle only containing wires with matching moduli.
    pub fn with_moduli(&self, moduli: &[u16]) -> Bundle<W> {
        let old_ws = self.wires();
        let mut new_ws = Vec::with_capacity(moduli.len());
        for &p in moduli {
            if let Some(w) = old_ws.iter().find(|&x| x.modulus() == p) {
                new_ws.push(w.clone());
            } else {
                panic!("Bundle::with_moduli: no {} modulus in bundle", p);
            }
        }
        Bundle(new_ws)
    }
}

/// DSL for the basic computations supported by fancy-garbling.
pub trait Fancy {
    /// The underlying wire datatype created by an object implementing `Fancy`.
    type Item: Clone + HasModulus;

    /// Errors which may be thrown by the users of Fancy.
    type Error: std::fmt::Debug + std::fmt::Display;

    /// Create an input for the garbler with modulus `q` and optional garbler-private value `x`.
    fn garbler_input(
        &self,
        ix: Option<SyncIndex>,
        q: u16,
        opt_x: Option<u16>,
    ) -> Result<Self::Item, FancyError<Self::Error>>;

    /// Create an input for the evaluator with modulus `q`.
    fn evaluator_input(
        &self,
        ix: Option<SyncIndex>,
        q: u16,
    ) -> Result<Self::Item, FancyError<Self::Error>>;

    /// Create a constant `x` with modulus `q`.
    fn constant(
        &self,
        ix: Option<SyncIndex>,
        x: u16,
        q: u16,
    ) -> Result<Self::Item, FancyError<Self::Error>>;

    /// Add `x` and `y`.
    fn add(&self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, FancyError<Self::Error>>;

    /// Subtract `x` and `y`.
    fn sub(&self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, FancyError<Self::Error>>;

    /// Multiply `x` times the constant `c`.
    fn cmul(&self, x: &Self::Item, c: u16) -> Result<Self::Item, FancyError<Self::Error>>;

    /// Multiply `x` and `y`.
    fn mul(
        &self,
        ix: Option<SyncIndex>,
        x: &Self::Item,
        y: &Self::Item,
    ) -> Result<Self::Item, FancyError<Self::Error>>;

    /// Project `x` according to the truth table `tt`. Resulting wire has modulus `q`.
    ///
    /// Optional `tt` is useful for hiding the gate from evaluator.
    fn proj(
        &self,
        ix: Option<SyncIndex>,
        x: &Self::Item,
        q: u16,
        tt: Option<Vec<u16>>,
    ) -> Result<Self::Item, FancyError<Self::Error>>;

    /// Process this wire as output.
    fn output(&self, ix: Option<SyncIndex>, x: &Self::Item) -> Result<(), FancyError<Self::Error>>;

    ////////////////////////////////////////////////////////////////////////////////
    // synchronization

    /// Start synchronization of internal messages.
    ///
    /// Optional, throws `FancyError::NotImplemented` if used without an implementation.
    fn begin_sync(&self, _num_indices: SyncIndex) -> Result<(), FancyError<Self::Error>> {
        Err(FancyError::NotImplemented)
    }

    /// Declare this index to be done.
    ///
    /// Optional, throws `FancyError::NotImplemented` if used without an implementation.
    fn finish_index(&self, _ix: SyncIndex) -> Result<(), FancyError<Self::Error>> {
        Err(FancyError::NotImplemented)
    }

    ////////////////////////////////////////////////////////////////////////////////
    // Functions built on top of basic fancy operations.

    /// Create `n` garbler inputs with the moduli `qs` and optional inputs `xs`.
    fn garbler_inputs(
        &self,
        ix: Option<SyncIndex>,
        qs: &[u16],
        opt_xs: Option<Vec<u16>>,
    ) -> Result<Vec<Self::Item>, FancyError<Self::Error>> {
        let xs = to_vec_option(opt_xs, qs.len());
        qs.iter()
            .zip(xs)
            .map(|(&q, x)| self.garbler_input(ix, q, x))
            .collect()
    }

    /// Create `n` evaluator inputs with the moduli `qs`.
    fn evaluator_inputs(
        &self,
        ix: Option<SyncIndex>,
        qs: &[u16],
    ) -> Result<Vec<Self::Item>, FancyError<Self::Error>> {
        qs.iter().map(|&q| self.evaluator_input(ix, q)).collect()
    }

    /// Sum up a slice of wires.
    fn add_many(&self, args: &[Self::Item]) -> Result<Self::Item, FancyError<Self::Error>> {
        if args.len() < 2 {
            return Err(FancyError::InvalidArgNum {
                got: args.len(),
                needed: 2,
            });
        }
        let mut z = args[0].clone();
        for x in args.iter().skip(1) {
            z = self.add(&z, x)?;
        }
        Ok(z)
    }

    /// Xor is just addition, with the requirement that `x` and `y` are mod 2.
    fn xor(&self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, FancyError<Self::Error>> {
        if x.modulus() != 2 {
            return Err(FancyError::InvalidArgMod {
                got: x.modulus(),
                needed: 2,
            });
        }
        if y.modulus() != 2 {
            return Err(FancyError::InvalidArgMod {
                got: y.modulus(),
                needed: 2,
            });
        }
        self.add(x, y)
    }

    /// Negate by xoring `x` with `1`.
    fn negate(
        &self,
        ix: Option<SyncIndex>,
        x: &Self::Item,
    ) -> Result<Self::Item, FancyError<Self::Error>> {
        if x.modulus() != 2 {
            return Err(FancyError::InvalidArgMod {
                got: x.modulus(),
                needed: 2,
            });
        }
        let one = self.constant(ix, 1, 2)?;
        self.xor(x, &one)
    }

    /// And is just multiplication, with the requirement that `x` and `y` are mod 2.
    fn and(
        &self,
        ix: Option<SyncIndex>,
        x: &Self::Item,
        y: &Self::Item,
    ) -> Result<Self::Item, FancyError<Self::Error>> {
        if x.modulus() != 2 {
            return Err(FancyError::InvalidArgMod {
                got: x.modulus(),
                needed: 2,
            });
        }
        if y.modulus() != 2 {
            return Err(FancyError::InvalidArgMod {
                got: y.modulus(),
                needed: 2,
            });
        }
        self.mul(ix, x, y)
    }

    /// Or uses Demorgan's Rule implemented with multiplication and negation.
    fn or(
        &self,
        ix: Option<SyncIndex>,
        x: &Self::Item,
        y: &Self::Item,
    ) -> Result<Self::Item, FancyError<Self::Error>> {
        if x.modulus() != 2 {
            return Err(FancyError::InvalidArgMod {
                got: x.modulus(),
                needed: 2,
            });
        }
        if y.modulus() != 2 {
            return Err(FancyError::InvalidArgMod {
                got: y.modulus(),
                needed: 2,
            });
        }
        let notx = self.negate(ix, x)?;
        let noty = self.negate(ix, y)?;
        let z = self.and(ix, &notx, &noty)?;
        self.negate(ix, &z)
    }

    /// Returns 1 if all wires equal 1.
    fn and_many(
        &self,
        ix: Option<SyncIndex>,
        args: &[Self::Item],
    ) -> Result<Self::Item, FancyError<Self::Error>> {
        if args.len() < 2 {
            return Err(FancyError::InvalidArgNum {
                got: args.len(),
                needed: 2,
            });
        }
        args.iter()
            .skip(1)
            .fold(Ok(args[0].clone()), |acc, x| self.and(ix, &(acc?), x))
    }

    /// Returns 1 if any wire equals 1.
    fn or_many(
        &self,
        ix: Option<SyncIndex>,
        args: &[Self::Item],
    ) -> Result<Self::Item, FancyError<Self::Error>> {
        if args.len() < 2 {
            return Err(FancyError::InvalidArgNum {
                got: args.len(),
                needed: 2,
            });
        }
        args.iter()
            .skip(1)
            .fold(Ok(args[0].clone()), |acc, x| self.or(ix, &(acc?), x))
    }

    /// Change the modulus of `x` to `to_modulus` using a projection gate.
    fn mod_change(
        &self,
        ix: Option<SyncIndex>,
        x: &Self::Item,
        to_modulus: u16,
    ) -> Result<Self::Item, FancyError<Self::Error>> {
        let from_modulus = x.modulus();
        if from_modulus == to_modulus {
            return Ok(x.clone());
        }
        let tab = (0..from_modulus).map(|x| x % to_modulus).collect_vec();
        self.proj(ix, x, to_modulus, Some(tab))
    }

    /// Binary adder. Returns the result and the carry.
    fn adder(
        &self,
        ix: Option<SyncIndex>,
        x: &Self::Item,
        y: &Self::Item,
        carry_in: Option<&Self::Item>,
    ) -> Result<(Self::Item, Self::Item), FancyError<Self::Error>> {
        if x.modulus() != 2 {
            return Err(FancyError::InvalidArgMod {
                got: x.modulus(),
                needed: 2,
            });
        }
        if y.modulus() != 2 {
            return Err(FancyError::InvalidArgMod {
                got: y.modulus(),
                needed: 2,
            });
        }
        if let Some(c) = carry_in {
            let z1 = self.xor(x, y)?;
            let z2 = self.xor(&z1, c)?;
            let z3 = self.xor(x, c)?;
            let z4 = self.and(ix, &z1, &z3)?;
            let carry = self.xor(&z4, x)?;
            Ok((z2, carry))
        } else {
            let z = self.xor(x, y)?;
            let carry = self.and(ix, x, y)?;
            Ok((z, carry))
        }
    }

    /// If `b=0` returns `x` else `y`.
    fn mux(
        &self,
        ix: Option<SyncIndex>,
        b: &Self::Item,
        x: &Self::Item,
        y: &Self::Item,
    ) -> Result<Self::Item, FancyError<Self::Error>> {
        let notb = self.negate(ix, b)?;
        let xsel = self.and(ix, &notb, x)?;
        let ysel = self.and(ix, b, y)?;
        self.add(&xsel, &ysel)
    }

    /// If `x=0` return the constant `b1` else return `b2`. Folds constants if possible.
    fn mux_constant_bits(
        &self,
        ix: Option<SyncIndex>,
        x: &Self::Item,
        b1: bool,
        b2: bool,
    ) -> Result<Self::Item, FancyError<Self::Error>> {
        if x.modulus() != 2 {
            return Err(FancyError::InvalidArgMod {
                got: x.modulus(),
                needed: 2,
            });
        }
        if !b1 && b2 {
            Ok(x.clone())
        } else if b1 && !b2 {
            self.negate(ix, x)
        } else if !b1 && !b2 {
            self.constant(ix, 0, 2)
        } else {
            self.constant(ix, 1, 2)
        }
    }

    /// Output a slice of wires.
    fn outputs(
        &self,
        ix: Option<SyncIndex>,
        xs: &[Self::Item],
    ) -> Result<(), FancyError<Self::Error>> {
        for x in xs.iter() {
            self.output(ix, x)?;
        }
        Ok(())
    }
}

/// Extension trait for `Fancy` providing advanced gadgets based on bundles of wires.
pub trait BundleGadgets: Fancy {
    ////////////////////////////////////////////////////////////////////////////////
    // Bundle creation

    /// Crate an input bundle for the garbler using moduli `ps` and optional inputs `xs`.
    fn garbler_input_bundle(
        &self,
        ix: Option<SyncIndex>,
        ps: &[u16],
        opt_xs: Option<Vec<u16>>,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        let xs = to_vec_option(opt_xs, ps.len());
        ps.iter()
            .zip(xs)
            .map(|(&p, x)| self.garbler_input(ix, p, x))
            .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()
            .map(Bundle)
    }

    /// Crate an input bundle for the evaluator using moduli `ps`.
    fn evaluator_input_bundle(
        &self,
        ix: Option<SyncIndex>,
        ps: &[u16],
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        ps.iter()
            .map(|&p| self.evaluator_input(ix, p))
            .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()
            .map(Bundle)
    }

    /// Crate an input bundle for the garbler using composite CRT modulus `q` and optional
    /// input `x`.
    fn garbler_input_bundle_crt(
        &self,
        ix: Option<SyncIndex>,
        q: u128,
        opt_x: Option<u128>,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        self.garbler_input_bundle(ix, &util::factor(q), opt_x.map(|x| util::crt_factor(x, q)))
    }

    /// Crate an input bundle for the evaluator using composite CRT modulus `q`.
    fn evaluator_input_bundle_crt(
        &self,
        ix: Option<SyncIndex>,
        q: u128,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        self.evaluator_input_bundle(ix, &util::factor(q))
    }

    /// Create an input bundle for the garbler using `nbits` base 2 inputs and optional input `x`.
    fn garbler_input_bundle_binary(
        &self,
        ix: Option<SyncIndex>,
        nbits: usize,
        opt_x: Option<u128>,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        self.garbler_input_bundle(
            ix,
            &vec![2; nbits],
            opt_x.map(|x| util::u128_to_bits(x, nbits)),
        )
    }

    /// Create an input bundle for the evaluator using n base 2 inputs.
    fn evaluator_input_bundle_binary(
        &self,
        ix: Option<SyncIndex>,
        n: usize,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        self.evaluator_input_bundle(ix, &vec![2; n])
    }

    /// Creates a bundle of constant wires using moduli `ps`.
    fn constant_bundle(
        &self,
        ix: Option<SyncIndex>,
        xs: &[u16],
        ps: &[u16],
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        xs.iter()
            .zip(ps.iter())
            .map(|(&x, &p)| self.constant(ix, x, p))
            .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()
            .map(Bundle)
    }

    /// Creates a bundle of constant wires for the CRT representation of `x` under
    /// composite modulus `q`.
    fn constant_bundle_crt(
        &self,
        ix: Option<SyncIndex>,
        x: u128,
        q: u128,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        let ps = util::factor(q);
        let xs = ps.iter().map(|&p| (x % p as u128) as u16).collect_vec();
        self.constant_bundle(ix, &xs, &ps)
    }

    /// Create a constant bundle using base 2 inputs.
    fn constant_bundle_binary(
        &self,
        ix: Option<SyncIndex>,
        bits: &[u16],
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        self.constant_bundle(ix, bits, &vec![2; bits.len()])
    }

    /// Create `n` garbler input bundles, using moduli `ps` and optional inputs `xs`.
    fn garbler_input_bundles(
        &self,
        ix: Option<SyncIndex>,
        ps: &[u16],
        n: usize,
        opt_xs: Option<Vec<Vec<u16>>>,
    ) -> Result<Vec<Bundle<Self::Item>>, FancyError<Self::Error>> {
        if let Some(inps) = opt_xs {
            if inps.len() != n {
                return Err(FancyError::InvalidArgNum {
                    got: inps.len(),
                    needed: n,
                });
            }
            inps.into_iter()
                .map(|xs| self.garbler_input_bundle(ix, ps, Some(xs)))
                .collect()
        } else {
            (0..n)
                .map(|_| self.garbler_input_bundle(ix, ps, None))
                .collect()
        }
    }

    /// Create `n` evaluator input bundles, using moduli `ps`.
    fn evaluator_input_bundles(
        &self,
        ix: Option<SyncIndex>,
        ps: &[u16],
        n: usize,
    ) -> Result<Vec<Bundle<Self::Item>>, FancyError<Self::Error>> {
        (0..n)
            .map(|_| self.evaluator_input_bundle(ix, ps))
            .collect()
    }

    /// Create `n` garbler input bundles, under composite CRT modulus `q` and optional
    /// inputs `xs`.
    fn garbler_input_bundles_crt(
        &self,
        ix: Option<SyncIndex>,
        q: u128,
        n: usize,
        opt_xs: Option<Vec<u128>>,
    ) -> Result<Vec<Bundle<Self::Item>>, FancyError<Self::Error>> {
        if let Some(xs) = opt_xs {
            if xs.len() != n {
                return Err(FancyError::InvalidArgNum {
                    got: xs.len(),
                    needed: n,
                });
            }
            xs.into_iter()
                .map(|x| self.garbler_input_bundle_crt(ix, q, Some(x)))
                .collect()
        } else {
            (0..n)
                .map(|_| self.garbler_input_bundle_crt(ix, q, None))
                .collect()
        }
    }

    /// Create `n` evaluator input bundles, under composite CRT modulus `q`.
    fn evaluator_input_bundles_crt(
        &self,
        ix: Option<SyncIndex>,
        q: u128,
        n: usize,
    ) -> Result<Vec<Bundle<Self::Item>>, FancyError<Self::Error>> {
        (0..n)
            .map(|_| self.evaluator_input_bundle_crt(ix, q))
            .collect()
    }

    /// Output the wires that make up a bundle.
    fn output_bundle(
        &self,
        ix: Option<SyncIndex>,
        x: &Bundle<Self::Item>,
    ) -> Result<(), FancyError<Self::Error>> {
        for w in x.wires() {
            self.output(ix, w)?;
        }
        Ok(())
    }

    /// Output a slice of bundles.
    fn output_bundles(
        &self,
        ix: Option<SyncIndex>,
        xs: &[Bundle<Self::Item>],
    ) -> Result<(), FancyError<Self::Error>> {
        for x in xs.iter() {
            self.output_bundle(ix, x)?;
        }
        Ok(())
    }

    ////////////////////////////////////////////////////////////////////////////////
    // High-level computations dealing with bundles.

    /// Add two wire bundles, residue by residue.
    fn add_bundles(
        &self,
        x: &Bundle<Self::Item>,
        y: &Bundle<Self::Item>,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        if x.wires().len() != y.wires().len() {
            return Err(FancyError::InvalidArgNum {
                got: y.wires().len(),
                needed: x.wires().len(),
            });
        }
        x.wires()
            .iter()
            .zip(y.wires().iter())
            .map(|(x, y)| self.add(x, y))
            .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()
            .map(Bundle)
    }

    /// Subtract two wire bundles, residue by residue.
    fn sub_bundles(
        &self,
        x: &Bundle<Self::Item>,
        y: &Bundle<Self::Item>,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        if x.wires().len() != y.wires().len() {
            return Err(FancyError::InvalidArgNum {
                got: y.wires().len(),
                needed: x.wires().len(),
            });
        }
        x.wires()
            .iter()
            .zip(y.wires().iter())
            .map(|(x, y)| self.sub(x, y))
            .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()
            .map(Bundle)
    }

    /// Multiplies each wire in `x` by the corresponding residue of `c`.
    fn cmul_bundle(
        &self,
        x: &Bundle<Self::Item>,
        c: u128,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        let cs = util::crt(c, &x.moduli());
        x.wires()
            .iter()
            .zip(cs.into_iter())
            .map(|(x, c)| self.cmul(x, c))
            .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()
            .map(Bundle)
    }

    /// Multiply `x` with `y`.
    fn mul_bundles(
        &self,
        ix: Option<SyncIndex>,
        x: &Bundle<Self::Item>,
        y: &Bundle<Self::Item>,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        x.wires()
            .iter()
            .zip(y.wires().iter())
            .map(|(x, y)| self.mul(ix, x, y))
            .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()
            .map(Bundle)
    }

    /// Exponentiate `x` by the constant `c`.
    fn cexp_bundle(
        &self,
        ix: Option<SyncIndex>,
        x: &Bundle<Self::Item>,
        c: u16,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        x.wires()
            .iter()
            .map(|x| {
                let p = x.modulus();
                let tab = (0..p)
                    .map(|x| ((x as u64).pow(c as u32) % p as u64) as u16)
                    .collect_vec();
                self.proj(ix, x, p, Some(tab))
            })
            .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()
            .map(Bundle)
    }

    /// Compute the remainder with respect to modulus `p`.
    fn rem_bundle(
        &self,
        ix: Option<SyncIndex>,
        x: &Bundle<Self::Item>,
        p: u16,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        let i = x
            .moduli()
            .iter()
            .position(|&q| p == q)
            .ok_or(FancyError::InvalidArg {
                desc: "p is not a moduli in this bundle!".to_string(),
            })?;
        let w = &x.wires()[i];
        x.moduli()
            .iter()
            .map(|&q| self.mod_change(ix, w, q))
            .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()
            .map(Bundle)
    }

    /// Compute `x == y`. Returns a wire encoding the result mod 2.
    fn eq_bundles(
        &self,
        ix: Option<SyncIndex>,
        x: &Bundle<Self::Item>,
        y: &Bundle<Self::Item>,
    ) -> Result<Self::Item, FancyError<Self::Error>> {
        if x.moduli() != y.moduli() {
            return Err(FancyError::UnequalModuli);
        }
        let wlen = x.wires().len() as u16;
        let zs = x
            .wires()
            .iter()
            .zip_eq(y.wires().iter())
            .map(|(x, y)| {
                // compute (x-y == 0) for each residue
                let z = self.sub(x, y)?;
                let mut eq_zero_tab = vec![0; x.modulus() as usize];
                eq_zero_tab[0] = 1;
                self.proj(ix, &z, wlen + 1, Some(eq_zero_tab))
            })
            .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()?;
        // add up the results, and output whether they equal zero or not, mod 2
        let z = self.add_many(&zs)?;
        let b = zs.len();
        let mut tab = vec![0; b + 1];
        tab[b] = 1;
        self.proj(ix, &z, 2, Some(tab))
    }

    /// Mixed radix addition.
    fn mixed_radix_addition(
        &self,
        ix: Option<SyncIndex>,
        xs: &[Bundle<Self::Item>],
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        let nargs = xs.len();
        let n = xs[0].wires().len();

        if nargs < 2 {
            return Err(FancyError::InvalidArgNum {
                got: nargs,
                needed: 2,
            });
        }
        if !xs.iter().all(|x| x.moduli() == xs[0].moduli()) {
            return Err(FancyError::UnequalModuli);
        }

        let mut digit_carry = None;
        let mut carry_carry = None;
        let mut max_carry = 0;

        let mut res = Vec::with_capacity(n);

        for i in 0..n {
            // all the ith digits, in one vec
            let ds = xs.iter().map(|x| x.wires()[i].clone()).collect_vec();

            // compute the digit -- easy
            let digit_sum = self.add_many(&ds)?;
            let digit = digit_carry.map_or(Ok(digit_sum.clone()), |d| self.add(&digit_sum, &d))?;

            if i < n - 1 {
                // compute the carries
                let q = xs[0].wires()[i].modulus();
                // max_carry currently contains the max carry from the previous iteration
                let max_val = nargs as u16 * (q - 1) + max_carry;
                // now it is the max carry of this iteration
                max_carry = max_val / q;

                let modded_ds = ds
                    .iter()
                    .map(|d| self.mod_change(ix, d, max_val + 1))
                    .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()?;

                let carry_sum = self.add_many(&modded_ds)?;
                // add in the carry from the previous iteration
                let carry =
                    carry_carry.map_or(Ok(carry_sum.clone()), |c| self.add(&carry_sum, &c))?;

                // carry now contains the carry information, we just have to project it to
                // the correct moduli for the next iteration
                let next_mod = xs[0].wires()[i + 1].modulus();
                let tt = (0..=max_val).map(|i| (i / q) % next_mod).collect_vec();
                digit_carry = Some(self.proj(ix, &carry, next_mod, Some(tt))?);

                let next_max_val = nargs as u16 * (next_mod - 1) + max_carry;

                if i < n - 2 {
                    if max_carry < next_mod {
                        carry_carry = Some(self.mod_change(
                            ix,
                            digit_carry.as_ref().unwrap(),
                            next_max_val + 1,
                        )?);
                    } else {
                        let tt = (0..=max_val).map(|i| i / q).collect_vec();
                        carry_carry = Some(self.proj(ix, &carry, next_max_val + 1, Some(tt))?);
                    }
                } else {
                    // next digit is MSB so we dont need carry_carry
                    carry_carry = None;
                }
            } else {
                digit_carry = None;
                carry_carry = None;
            }
            res.push(digit);
        }
        Ok(Bundle(res))
    }

    /// Mixed radix addition only returning the MSB.
    fn mixed_radix_addition_msb_only(
        &self,
        ix: Option<SyncIndex>,
        xs: &[Bundle<Self::Item>],
    ) -> Result<Self::Item, FancyError<Self::Error>> {
        let nargs = xs.len();
        let n = xs[0].wires().len();

        if nargs < 2 {
            return Err(FancyError::InvalidArgNum {
                got: nargs,
                needed: 2,
            });
        }
        if !xs.iter().all(|x| x.moduli() == xs[0].moduli()) {
            return Err(FancyError::UnequalModuli);
        }

        let mut opt_carry = None;
        let mut max_carry = 0;

        for i in 0..n - 1 {
            // all the ith digits, in one vec
            let ds = xs.iter().map(|x| x.wires()[i].clone()).collect_vec();
            // compute the carry
            let q = xs[0].moduli()[i];
            // max_carry currently contains the max carry from the previous iteration
            let max_val = nargs as u16 * (q - 1) + max_carry;
            // now it is the max carry of this iteration
            max_carry = max_val / q;

            // mod change the digits to the max sum possible plus the max carry of the
            // previous iteration
            let modded_ds = ds
                .iter()
                .map(|d| self.mod_change(ix, d, max_val + 1))
                .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()?;
            // add them up
            let sum = self.add_many(&modded_ds)?;
            // add in the carry
            let sum_with_carry = opt_carry
                .as_ref()
                .map_or(Ok(sum.clone()), |c| self.add(&sum, &c))?;

            // carry now contains the carry information, we just have to project it to
            // the correct moduli for the next iteration. It will either be used to
            // compute the next carry, if i < n-2, or it will be used to compute the
            // output MSB, in which case it should be the modulus of the SB
            let next_mod = if i < n - 2 {
                nargs as u16 * (xs[0].moduli()[i + 1] - 1) + max_carry + 1
            } else {
                xs[0].moduli()[i + 1] // we will be adding the carry to the MSB
            };

            let tt = (0..=max_val).map(|i| (i / q) % next_mod).collect_vec();
            opt_carry = Some(self.proj(ix, &sum_with_carry, next_mod, Some(tt))?);
        }

        // compute the msb
        let ds = xs.iter().map(|x| x.wires()[n - 1].clone()).collect_vec();
        let digit_sum = self.add_many(&ds)?;
        opt_carry
            .as_ref()
            .map_or(Ok(digit_sum.clone()), |d| self.add(&digit_sum, &d))
    }

    ////////////////////////////////////////////////////////////////////////////////
    // Fancy functions based on Mike's fractional mixed radix trick.

    /// Helper function for advanced gadgets, returns the MSB of the fractional part of
    /// `X/M` where `M=product(ms)`.
    fn fractional_mixed_radix(
        &self,
        ix: Option<SyncIndex>,
        bun: &Bundle<Self::Item>,
        ms: &[u16],
    ) -> Result<Self::Item, FancyError<Self::Error>> {
        let ndigits = ms.len();

        let q = util::product(&bun.moduli());
        let M = util::product(ms);

        let mut ds = Vec::new();

        for wire in bun.wires().iter() {
            let p = wire.modulus();

            let mut tabs = vec![Vec::with_capacity(p as usize); ndigits];

            for x in 0..p {
                let crt_coef = util::inv(((q / p as u128) % p as u128) as i128, p as i128);
                let y = (M as f64 * x as f64 * crt_coef as f64 / p as f64).round() as u128 % M;
                let digits = util::as_mixed_radix(y, ms);
                for i in 0..ndigits {
                    tabs[i].push(digits[i]);
                }
            }

            let new_ds = tabs
                .into_iter()
                .enumerate()
                .map(|(i, tt)| self.proj(ix, wire, ms[i], Some(tt)))
                .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()?;

            ds.push(Bundle(new_ds));
        }

        self.mixed_radix_addition_msb_only(ix, &ds)
    }

    /// Compute `max(x,0)`.
    ///
    /// Optional output moduli.
    fn relu(
        &self,
        ix: Option<SyncIndex>,
        x: &Bundle<Self::Item>,
        accuracy: &str,
        output_moduli: Option<&[u16]>,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        let factors_of_m = &get_ms(x, accuracy);
        let res = self.fractional_mixed_radix(ix, x, factors_of_m)?;

        // project the MSB to 0/1, whether or not it is less than p/2
        let p = *factors_of_m.last().unwrap();
        let mask_tt = (0..p).map(|x| (x < p / 2) as u16).collect_vec();
        let mask = self.proj(ix, &res, 2, Some(mask_tt))?;

        // use the mask to either output x or 0
        output_moduli
            .map(|ps| x.with_moduli(ps))
            .as_ref()
            .unwrap_or(x)
            .wires()
            .iter()
            .map(|x| self.mul(ix, x, &mask))
            .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()
            .map(Bundle)
    }

    /// Return 0 if `x` is positive and 1 if `x` is negative.
    fn sign(
        &self,
        ix: Option<SyncIndex>,
        x: &Bundle<Self::Item>,
        accuracy: &str,
    ) -> Result<Self::Item, FancyError<Self::Error>> {
        let factors_of_m = &get_ms(x, accuracy);
        let res = self.fractional_mixed_radix(ix, x, factors_of_m)?;
        let p = *factors_of_m.last().unwrap();
        let tt = (0..p).map(|x| (x >= p / 2) as u16).collect_vec();
        self.proj(ix, &res, 2, Some(tt))
    }

    /// Return `if x >= 0 then 1 else -1`, where `-1` is interpreted as `Q-1`.
    ///
    /// If provided, will produce a bundle under `output_moduli` instead of `x.moduli()`
    fn sgn(
        &self,
        ix: Option<SyncIndex>,
        x: &Bundle<Self::Item>,
        accuracy: &str,
        output_moduli: Option<&[u16]>,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        let sign = self.sign(ix, x, accuracy)?;
        output_moduli
            .unwrap_or(&x.moduli())
            .into_iter()
            .map(|&p| {
                let tt = vec![1, p - 1];
                self.proj(ix, &sign, p, Some(tt))
            })
            .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()
            .map(Bundle)
    }

    /// Returns 1 if `x < y`. Works on both CRT and binary bundles.
    ///
    /// Binary ignores accuracy argument.
    fn lt(
        &self,
        ix: Option<SyncIndex>,
        x: &Bundle<Self::Item>,
        y: &Bundle<Self::Item>,
        accuracy: &str,
    ) -> Result<Self::Item, FancyError<Self::Error>> {
        if x.is_binary() {
            let (_, z) = self.binary_subtraction(ix, x, y)?;
            Ok(z)
        } else {
            let z = self.sub_bundles(x, y)?;
            self.sign(ix, &z, accuracy)
        }
    }

    /// Returns 1 if `x >= y`. Works on both CRT and binary bundles.
    fn geq(
        &self,
        ix: Option<SyncIndex>,
        x: &Bundle<Self::Item>,
        y: &Bundle<Self::Item>,
        accuracy: &str,
    ) -> Result<Self::Item, FancyError<Self::Error>> {
        let z = self.lt(ix, x, y, accuracy)?;
        self.negate(ix, &z)
    }

    /// Compute the maximum bundle in `xs`.
    fn max(
        &self,
        ix: Option<SyncIndex>,
        xs: &[Bundle<Self::Item>],
        accuracy: &str,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        if xs.len() < 2 {
            return Err(FancyError::InvalidArgNum {
                got: xs.len(),
                needed: 2,
            });
        }
        xs.iter().skip(1).fold(Ok(xs[0].clone()), |x, y| {
            let pos = self.lt(ix, &(x?), y, accuracy)?;
            let neg = self.negate(ix, &pos)?;
            x?.wires()
                .iter()
                .zip(y.wires().iter())
                .map(|(x, y)| {
                    let xp = self.mul(ix, x, &neg)?;
                    let yp = self.mul(ix, y, &pos)?;
                    self.add(&xp, &yp)
                })
                .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()
                .map(Bundle)
        })
    }

    ////////////////////////////////////////////////////////////////////////////////
    // other gadgets

    /// Binary addition. Returns the result and the carry.
    fn binary_addition(
        &self,
        ix: Option<SyncIndex>,
        xs: &Bundle<Self::Item>,
        ys: &Bundle<Self::Item>,
    ) -> Result<(Bundle<Self::Item>, Self::Item), FancyError<Self::Error>> {
        if xs.moduli() != ys.moduli() {
            return Err(FancyError::UnequalModuli);
        }
        let xwires = xs.wires();
        let ywires = ys.wires();
        let (mut z, mut c) = self.adder(ix, &xwires[0], &ywires[0], None)?;
        let mut bs = vec![z];
        for i in 1..xwires.len() {
            let res = self.adder(ix, &xwires[i], &ywires[i], Some(&c))?;
            z = res.0;
            c = res.1;
            bs.push(z);
        }
        Ok((Bundle(bs), c))
    }

    /// Binary addition. Avoids creating extra gates for the final carry.
    fn binary_addition_no_carry(
        &self,
        ix: Option<SyncIndex>,
        xs: &Bundle<Self::Item>,
        ys: &Bundle<Self::Item>,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        if xs.moduli() != ys.moduli() {
            return Err(FancyError::UnequalModuli);
        }
        let xwires = xs.wires();
        let ywires = ys.wires();
        let (mut z, mut c) = self.adder(ix, &xwires[0], &ywires[0], None)?;
        let mut bs = vec![z];
        for i in 1..xwires.len() - 1 {
            let res = self.adder(ix, &xwires[i], &ywires[i], Some(&c))?;
            z = res.0;
            c = res.1;
            bs.push(z);
        }
        z = self.add_many(&[
            xwires.last().unwrap().clone(),
            ywires.last().unwrap().clone(),
            c,
        ])?;
        bs.push(z);
        Ok(Bundle(bs))
    }

    /// Binary multiplication.
    ///
    /// Returns the lower-order half of the output bits, ie a number with the same number
    /// of bits as the inputs.
    fn binary_multiplication_lower_half(
        &self,
        ix: Option<SyncIndex>,
        xs: &Bundle<Self::Item>,
        ys: &Bundle<Self::Item>,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        if xs.moduli() != ys.moduli() {
            return Err(FancyError::UnequalModuli);
        }

        let xwires = xs.wires();
        let ywires = ys.wires();

        let mut sum = xwires
            .iter()
            .map(|x| self.and(ix, x, &ywires[0]))
            .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()
            .map(Bundle)?;

        for i in 1..xwires.len() {
            let mul = xwires
                .iter()
                .map(|x| self.and(ix, x, &ywires[i]))
                .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()
                .map(Bundle)?;
            let shifted = self.shift(ix, &mul, i)?;
            sum = self.binary_addition_no_carry(ix, &sum, &shifted)?;
        }

        Ok(sum)
    }

    /// Compute the twos complement of the input bundle (which must be base 2).
    fn twos_complement(
        &self,
        ix: Option<SyncIndex>,
        xs: &Bundle<Self::Item>,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        let not_xs = xs
            .wires()
            .iter()
            .map(|x| self.negate(ix, x))
            .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()?;
        let zero = self.constant(ix, 0, 2)?;
        let mut const1 = vec![zero; xs.size()];
        const1[0] = self.constant(ix, 1, 2)?;
        self.binary_addition_no_carry(ix, &Bundle(not_xs), &Bundle(const1))
    }

    /// Subtract two binary bundles. Returns the result and whether it overflowed.
    fn binary_subtraction(
        &self,
        ix: Option<SyncIndex>,
        xs: &Bundle<Self::Item>,
        ys: &Bundle<Self::Item>,
    ) -> Result<(Bundle<Self::Item>, Self::Item), FancyError<Self::Error>> {
        let neg_ys = self.twos_complement(ix, &ys)?;
        let (zs, c) = self.binary_addition(ix, &xs, &neg_ys)?;
        Ok((zs, self.negate(ix, &c)?))
    }

    /// If b=0 then return x, else return y.
    fn multiplex(
        &self,
        ix: Option<SyncIndex>,
        b: &Self::Item,
        x: &Bundle<Self::Item>,
        y: &Bundle<Self::Item>,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        x.wires()
            .iter()
            .zip(y.wires().iter())
            .map(|(xwire, ywire)| self.mux(ix, b, xwire, ywire))
            .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()
            .map(Bundle)
    }

    /// If `x=0` return `c1` as a bundle of constant bits, else return `c2`.
    fn multiplex_constant_bits(
        &self,
        ix: Option<SyncIndex>,
        x: &Self::Item,
        c1: u128,
        c2: u128,
        nbits: usize,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        let c1_bs = util::u128_to_bits(c1, nbits)
            .into_iter()
            .map(|x: u16| x > 0)
            .collect_vec();
        let c2_bs = util::u128_to_bits(c2, nbits)
            .into_iter()
            .map(|x: u16| x > 0)
            .collect_vec();
        c1_bs
            .into_iter()
            .zip(c2_bs.into_iter())
            .map(|(b1, b2)| self.mux_constant_bits(ix, x, b1, b2))
            .collect::<Result<Vec<Self::Item>, FancyError<Self::Error>>>()
            .map(Bundle)
    }

    /// Shift residues, replacing them with zeros in the modulus of the least signifigant residue.
    fn shift(
        &self,
        ix: Option<SyncIndex>,
        x: &Bundle<Self::Item>,
        n: usize,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        let mut ws = x.wires().to_vec();
        let zero = self.constant(ix, 0, ws.last().unwrap().modulus())?;
        for _ in 0..n {
            ws.pop();
            ws.insert(0, zero.clone());
        }
        Ok(Bundle(ws))
    }

    /// Write the constant in binary and that gives you the shift amounts, Eg.. 7x is 4x+2x+x.
    fn binary_cmul(
        &self,
        ix: Option<SyncIndex>,
        x: &Bundle<Self::Item>,
        c: u128,
        nbits: usize,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        if !x.is_binary() {
            return Err(FancyError::ArgNotBinary);
        }
        let zero = self.constant_bundle(ix, &vec![0; nbits], &vec![2; nbits])?;
        util::u128_to_bits(c, nbits)
            .into_iter()
            .enumerate()
            .filter_map(|(i, b)| if b > 0 { Some(i) } else { None })
            .fold(Ok(zero), |z, shift_amt| {
                let s = self.shift(ix, x, shift_amt)?;
                self.binary_addition_no_carry(ix, &(z?), &s)
            })
    }

    /// Compute the absolute value of a binary bundle.
    fn abs(
        &self,
        ix: Option<SyncIndex>,
        x: &Bundle<Self::Item>,
    ) -> Result<Bundle<Self::Item>, FancyError<Self::Error>> {
        if !x.is_binary() {
            return Err(FancyError::ArgNotBinary);
        }
        let sign = x.wires().last().unwrap();
        let negated = self.twos_complement(ix, x)?;
        self.multiplex(ix, &sign, x, &negated)
    }
}

impl<F: Fancy> BundleGadgets for F {}

/// Compute the ms needed for the number of CRT primes in `x`, with accuracy acc.
///
/// Supported accuracy: ["100%", "99.9%", "99%"]
fn get_ms<W: Clone + HasModulus>(x: &Bundle<W>, accuracy: &str) -> Vec<u16> {
    match accuracy {
        "100%" => match x.moduli().len() {
            3 => vec![2; 5],
            4 => vec![3, 26],
            5 => vec![3, 4, 54],
            6 => vec![5, 5, 5, 60],
            7 => vec![5, 6, 6, 7, 86],
            8 => vec![5, 7, 8, 8, 9, 98],
            9 => vec![5, 5, 7, 7, 7, 7, 7, 76],
            10 => vec![5, 5, 6, 6, 6, 6, 11, 11, 202],
            11 => vec![5, 5, 5, 5, 5, 6, 6, 6, 7, 7, 8, 150],
            n => panic!("unknown exact Ms for {} primes!", n),
        },
        "99.999%" => match x.moduli().len() {
            8 => vec![5, 5, 6, 7, 102],
            9 => vec![5, 5, 6, 7, 114],
            10 => vec![5, 6, 6, 7, 102],
            11 => vec![5, 5, 6, 7, 130],
            n => panic!("unknown 99.999% accurate Ms for {} primes!", n),
        },
        "99.99%" => match x.moduli().len() {
            6 => vec![5, 5, 5, 42],
            7 => vec![4, 5, 6, 88],
            8 => vec![4, 5, 7, 78],
            9 => vec![5, 5, 6, 84],
            10 => vec![4, 5, 6, 112],
            11 => vec![7, 11, 174],
            n => panic!("unknown 99.99% accurate Ms for {} primes!", n),
        },
        "99.9%" => match x.moduli().len() {
            5 => vec![3, 5, 30],
            6 => vec![4, 5, 48],
            7 => vec![4, 5, 60],
            8 => vec![3, 5, 78],
            9 => vec![9, 140],
            10 => vec![7, 190],
            n => panic!("unknown 99.9% accurate Ms for {} primes!", n),
        },
        "99%" => match x.moduli().len() {
            4 => vec![3, 18],
            5 => vec![3, 36],
            6 => vec![3, 40],
            7 => vec![3, 40],
            8 => vec![126],
            9 => vec![138],
            10 => vec![140],
            n => panic!("unknown 99% accurate Ms for {} primes!", n),
        },
        _ => panic!("get_ms: unsupported accuracy {}", accuracy),
    }
}

fn to_vec_option<T>(opt_xs: Option<Vec<T>>, len: usize) -> Vec<Option<T>> {
    opt_xs
        .map(|vals| {
            // transform option of slice into vec of options
            vals.into_iter().map(Some).collect()
        })
        .unwrap_or((0..len).map(|_| None).collect())
}
