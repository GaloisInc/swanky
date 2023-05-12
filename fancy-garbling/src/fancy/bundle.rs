use crate::{
    errors::FancyError,
    fancy::{Fancy, HasModulus},
    FancyArithmetic, FancyBinary,
};
use itertools::Itertools;
use std::ops::Index;

/// A collection of wires, useful for the garbled gadgets defined by `BundleGadgets`.
#[derive(Clone)]
pub struct Bundle<W>(Vec<W>);

impl<W: Clone + HasModulus> Bundle<W> {
    /// Create a new bundle from some wires.
    pub fn new(ws: Vec<W>) -> Bundle<W> {
        Bundle(ws)
    }

    /// Return the moduli of all the wires in the bundle.
    pub fn moduli(&self) -> Vec<u16> {
        self.0.iter().map(HasModulus::modulus).collect()
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

    /// Pad the Bundle with val, n times.
    pub fn pad(&mut self, val: &W, n: usize) {
        for _ in 0..n {
            self.0.push(val.clone());
        }
    }

    /// Extract a wire from the Bundle, removing it and returning it.
    pub fn extract(&mut self, wire_index: usize) -> W {
        self.0.remove(wire_index)
    }

    /// Insert a wire from the Bundle
    pub fn insert(&mut self, wire_index: usize, val: W) {
        self.0.insert(wire_index, val)
    }

    /// push a wire onto the Bundle.
    pub fn push(&mut self, val: W) {
        self.0.push(val);
    }

    /// Pop a wire from the Bundle.
    pub fn pop(&mut self) -> Option<W> {
        self.0.pop()
    }

    /// Access the underlying iterator
    pub fn iter(&self) -> std::slice::Iter<W> {
        self.0.iter()
    }

    /// Reverse the wires
    pub fn reverse(&mut self) {
        self.0.reverse();
    }
}

impl<W: Clone + HasModulus> Index<usize> for Bundle<W> {
    type Output = W;

    fn index(&self, idx: usize) -> &Self::Output {
        self.0.index(idx)
    }
}

impl<F: Fancy> BundleGadgets for F {}
impl<F: FancyArithmetic> ArithmeticBundleGadgets for F {}
impl<F: FancyBinary> BinaryBundleGadgets for F {}

/// Arithmetic operations on wire bundles, extending the capability of `FancyArithmetic` operating
/// on individual wires.
pub trait ArithmeticBundleGadgets: FancyArithmetic {
    /// Add two wire bundles pairwise, zipping addition.
    ///
    /// In CRT this is plain addition. In binary this is xor.
    fn add_bundles(
        &mut self,
        x: &Bundle<Self::Item>,
        y: &Bundle<Self::Item>,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        if x.wires().len() != y.wires().len() {
            return Err(Self::Error::from(FancyError::InvalidArgNum {
                got: y.wires().len(),
                needed: x.wires().len(),
            }));
        }
        x.wires()
            .iter()
            .zip(y.wires().iter())
            .map(|(x, y)| self.add(x, y))
            .collect::<Result<Vec<Self::Item>, Self::Error>>()
            .map(Bundle::new)
    }

    /// Subtract two wire bundles, residue by residue.
    ///
    /// In CRT this is plain subtraction. In binary this is `xor`.
    fn sub_bundles(
        &mut self,
        x: &Bundle<Self::Item>,
        y: &Bundle<Self::Item>,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        if x.wires().len() != y.wires().len() {
            return Err(Self::Error::from(FancyError::InvalidArgNum {
                got: y.wires().len(),
                needed: x.wires().len(),
            }));
        }
        x.wires()
            .iter()
            .zip(y.wires().iter())
            .map(|(x, y)| self.sub(x, y))
            .collect::<Result<Vec<Self::Item>, Self::Error>>()
            .map(Bundle::new)
    }

    /// Multiply each wire in `x` with each wire in `y`, pairwise.
    ///
    /// In CRT this is plain multiplication. In binary this is `and`.
    fn mul_bundles(
        &mut self,
        x: &Bundle<Self::Item>,
        y: &Bundle<Self::Item>,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        x.wires()
            .iter()
            .zip(y.wires().iter())
            .map(|(x, y)| self.mul(x, y))
            .collect::<Result<Vec<Self::Item>, Self::Error>>()
            .map(Bundle::new)
    }

    /// Mixed radix addition.
    fn mixed_radix_addition(
        &mut self,
        xs: &[Bundle<Self::Item>],
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        let nargs = xs.len();
        if nargs < 1 {
            return Err(Self::Error::from(FancyError::InvalidArgNum {
                got: nargs,
                needed: 1,
            }));
        }

        let n = xs[0].wires().len();
        if !xs.iter().all(|x| x.moduli() == xs[0].moduli()) {
            return Err(Self::Error::from(FancyError::UnequalModuli));
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
                    .map(|d| self.mod_change(d, max_val + 1))
                    .collect::<Result<Vec<Self::Item>, Self::Error>>()?;

                let carry_sum = self.add_many(&modded_ds)?;
                // add in the carry from the previous iteration
                let carry =
                    carry_carry.map_or(Ok(carry_sum.clone()), |c| self.add(&carry_sum, &c))?;

                // carry now contains the carry information, we just have to project it to
                // the correct moduli for the next iteration
                let next_mod = xs[0].wires()[i + 1].modulus();
                let tt = (0..=max_val).map(|i| (i / q) % next_mod).collect_vec();
                digit_carry = Some(self.proj(&carry, next_mod, Some(tt))?);

                let next_max_val = nargs as u16 * (next_mod - 1) + max_carry;

                if i < n - 2 {
                    if max_carry < next_mod {
                        carry_carry =
                            Some(self.mod_change(digit_carry.as_ref().unwrap(), next_max_val + 1)?);
                    } else {
                        let tt = (0..=max_val).map(|i| i / q).collect_vec();
                        carry_carry = Some(self.proj(&carry, next_max_val + 1, Some(tt))?);
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
        &mut self,
        xs: &[Bundle<Self::Item>],
    ) -> Result<Self::Item, Self::Error> {
        let nargs = xs.len();
        if nargs < 1 {
            return Err(Self::Error::from(FancyError::InvalidArgNum {
                got: nargs,
                needed: 1,
            }));
        }

        let n = xs[0].wires().len();
        if !xs.iter().all(|x| x.moduli() == xs[0].moduli()) {
            return Err(Self::Error::from(FancyError::UnequalModuli));
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
                .map(|d| self.mod_change(d, max_val + 1))
                .collect::<Result<Vec<Self::Item>, Self::Error>>()?;
            // add them up
            let sum = self.add_many(&modded_ds)?;
            // add in the carry
            let sum_with_carry = opt_carry
                .as_ref()
                .map_or(Ok(sum.clone()), |c| self.add(&sum, c))?;

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
            opt_carry = Some(self.proj(&sum_with_carry, next_mod, Some(tt))?);
        }

        // compute the msb
        let ds = xs.iter().map(|x| x.wires()[n - 1].clone()).collect_vec();
        let digit_sum = self.add_many(&ds)?;
        opt_carry
            .as_ref()
            .map_or(Ok(digit_sum.clone()), |d| self.add(&digit_sum, d))
    }

    /// If b=0 then return 0, else return x.
    fn mask(
        &mut self,
        b: &Self::Item,
        x: &Bundle<Self::Item>,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        x.wires()
            .iter()
            .map(|xwire| self.mul(xwire, b))
            .collect::<Result<Vec<Self::Item>, Self::Error>>()
            .map(Bundle)
    }

    /// Compute `x == y`. Returns a wire encoding the result mod 2.
    fn eq_bundles(
        &mut self,
        x: &Bundle<Self::Item>,
        y: &Bundle<Self::Item>,
    ) -> Result<Self::Item, Self::Error> {
        if x.moduli() != y.moduli() {
            return Err(Self::Error::from(FancyError::UnequalModuli));
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
                self.proj(&z, wlen + 1, Some(eq_zero_tab))
            })
            .collect::<Result<Vec<Self::Item>, Self::Error>>()?;
        // add up the results, and output whether they equal zero or not, mod 2
        let z = self.add_many(&zs)?;
        let b = zs.len();
        let mut tab = vec![0; b + 1];
        tab[b] = 1;
        self.proj(&z, 2, Some(tab))
    }
}

/// Binary operations on wire bundles, extending the capability of `FancyBinary` operating
/// on individual wires.
pub trait BinaryBundleGadgets: FancyBinary {
    /// If b=0 then return x, else return y.
    fn multiplex(
        &mut self,
        b: &Self::Item,
        x: &Bundle<Self::Item>,
        y: &Bundle<Self::Item>,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        x.wires()
            .iter()
            .zip(y.wires().iter())
            .map(|(xwire, ywire)| self.mux(b, xwire, ywire))
            .collect::<Result<Vec<Self::Item>, Self::Error>>()
            .map(Bundle)
    }
}

/// Extension trait for Fancy which provides Bundle constructions which are not
/// necessarily CRT nor binary-based.
pub trait BundleGadgets: Fancy {
    /// Creates a bundle of constant wires using moduli `ps`.
    fn constant_bundle(
        &mut self,
        xs: &[u16],
        ps: &[u16],
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        xs.iter()
            .zip(ps.iter())
            .map(|(&x, &p)| self.constant(x, p))
            .collect::<Result<Vec<Self::Item>, Self::Error>>()
            .map(Bundle)
    }

    /// Output the wires that make up a bundle.
    fn output_bundle(&mut self, x: &Bundle<Self::Item>) -> Result<Option<Vec<u16>>, Self::Error> {
        let ws = x.wires();
        let mut outputs = Vec::with_capacity(ws.len());
        for w in ws.iter() {
            outputs.push(self.output(w)?);
        }
        Ok(outputs.into_iter().collect())
    }

    /// Output a slice of bundles.
    fn output_bundles(
        &mut self,
        xs: &[Bundle<Self::Item>],
    ) -> Result<Option<Vec<Vec<u16>>>, Self::Error> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            let z = self.output_bundle(x)?;
            zs.push(z);
        }
        Ok(zs.into_iter().collect())
    }

    ////////////////////////////////////////////////////////////////////////////////
    // gadgets which are neither CRT or binary

    /// Shift residues, replacing them with zeros in the modulus of the least signifigant
    /// residue. Maintains the length of the input.
    fn shift(
        &mut self,
        x: &Bundle<Self::Item>,
        n: usize,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        let mut ws = x.wires().to_vec();
        let zero = self.constant(0, ws.last().unwrap().modulus())?;
        for _ in 0..n {
            ws.pop();
            ws.insert(0, zero.clone());
        }
        Ok(Bundle(ws))
    }

    /// Shift residues, replacing them with zeros in the modulus of the least signifigant
    /// residue. Output is extended with n elements.
    fn shift_extend(
        &mut self,
        x: &Bundle<Self::Item>,
        n: usize,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        let mut ws = x.wires().to_vec();
        let zero = self.constant(0, ws.last().unwrap().modulus())?;
        for _ in 0..n {
            ws.insert(0, zero.clone());
        }
        Ok(Bundle(ws))
    }
}
