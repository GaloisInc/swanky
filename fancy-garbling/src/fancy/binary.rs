// -*- mode: rust; -*-
//
// This file is part of `fancy-garbling`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::{
    errors::FancyError,
    fancy::{
        bundle::{Bundle, BundleGadgets},
        Fancy, HasModulus,
    },
    util,
};
use core::ops::{Deref, DerefMut};
use itertools::Itertools;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use sgx_tstd::string::ToString;
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use sgx_tstd::vec;
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use sgx_tstd::vec::Vec;

/// Bundle which is explicitly binary representation.
#[derive(Clone)]
pub struct BinaryBundle<W>(Bundle<W>);

impl<W: Clone + HasModulus> BinaryBundle<W> {
    /// Create a new binary bundle from a vector of wires.
    pub fn new(ws: Vec<W>) -> BinaryBundle<W> {
        BinaryBundle(Bundle::new(ws))
    }

    /// Extract the underlying bundle from this binary bundle.
    pub fn extract(self) -> Bundle<W> {
        self.0
    }
}

impl<W: Clone + HasModulus> Deref for BinaryBundle<W> {
    type Target = Bundle<W>;

    fn deref(&self) -> &Bundle<W> {
        &self.0
    }
}

impl<W: Clone + HasModulus> DerefMut for BinaryBundle<W> {
    fn deref_mut(&mut self) -> &mut Bundle<W> {
        &mut self.0
    }
}

impl<W: Clone + HasModulus> From<Bundle<W>> for BinaryBundle<W> {
    fn from(b: Bundle<W>) -> BinaryBundle<W> {
        debug_assert!(b.moduli().iter().all(|&p| p == 2));
        BinaryBundle(b)
    }
}

impl<F: Fancy> BinaryGadgets for F {}

/// Extension trait for `Fancy` providing gadgets that operate over bundles of mod2 wires.
pub trait BinaryGadgets: Fancy + BundleGadgets {
    /// Create a constant bundle using base 2 inputs.
    fn bin_constant_bundle(
        &mut self,
        val: u128,
        nbits: usize,
    ) -> Result<BinaryBundle<Self::Item>, Self::Error> {
        self.constant_bundle(&util::u128_to_bits(val, nbits), &vec![2; nbits])
            .map(BinaryBundle)
    }

    /// Output a binary bundle and interpret the result as a `u128`.
    fn bin_output(&mut self, x: &BinaryBundle<Self::Item>) -> Result<Option<u128>, Self::Error> {
        Ok(self.output_bundle(x)?.map(|bs| util::u128_from_bits(&bs)))
    }

    /// Output a slice of binary bundles and interpret the results as a `u128`.
    fn bin_outputs(
        &mut self,
        xs: &[BinaryBundle<Self::Item>],
    ) -> Result<Option<Vec<u128>>, Self::Error> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            let z = self.bin_output(x)?;
            zs.push(z);
        }
        Ok(zs.into_iter().collect())
    }

    /// Xor the bits of two bundles together pairwise.
    fn bin_xor(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        y: &BinaryBundle<Self::Item>,
    ) -> Result<BinaryBundle<Self::Item>, Self::Error> {
        self.add_bundles(&x, &y).map(BinaryBundle)
    }

    /// And the bits of two bundles together pairwise.
    fn bin_and(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        y: &BinaryBundle<Self::Item>,
    ) -> Result<BinaryBundle<Self::Item>, Self::Error> {
        self.mul_bundles(&x, &y).map(BinaryBundle)
    }

    /// Or the bits of two bundles together pairwise.
    fn bin_or(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        y: &BinaryBundle<Self::Item>,
    ) -> Result<BinaryBundle<Self::Item>, Self::Error> {
        x.wires()
            .iter()
            .zip(y.wires().iter())
            .map(|(x, y)| self.or(x, y))
            .collect::<Result<Vec<Self::Item>, Self::Error>>()
            .map(BinaryBundle::new)
    }

    /// Binary addition. Returns the result and the carry.
    fn bin_addition(
        &mut self,
        xs: &BinaryBundle<Self::Item>,
        ys: &BinaryBundle<Self::Item>,
    ) -> Result<(BinaryBundle<Self::Item>, Self::Item), Self::Error> {
        if xs.moduli() != ys.moduli() {
            return Err(Self::Error::from(FancyError::UnequalModuli));
        }
        let xwires = xs.wires();
        let ywires = ys.wires();
        let (mut z, mut c) = self.adder(&xwires[0], &ywires[0], None)?;
        let mut bs = vec![z];
        for i in 1..xwires.len() {
            let res = self.adder(&xwires[i], &ywires[i], Some(&c))?;
            z = res.0;
            c = res.1;
            bs.push(z);
        }
        Ok((BinaryBundle::new(bs), c))
    }

    /// Binary addition. Avoids creating extra gates for the final carry.
    fn bin_addition_no_carry(
        &mut self,
        xs: &BinaryBundle<Self::Item>,
        ys: &BinaryBundle<Self::Item>,
    ) -> Result<BinaryBundle<Self::Item>, Self::Error> {
        if xs.moduli() != ys.moduli() {
            return Err(Self::Error::from(FancyError::UnequalModuli));
        }
        let xwires = xs.wires();
        let ywires = ys.wires();
        let (mut z, mut c) = self.adder(&xwires[0], &ywires[0], None)?;
        let mut bs = vec![z];
        for i in 1..xwires.len() - 1 {
            let res = self.adder(&xwires[i], &ywires[i], Some(&c))?;
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
        Ok(BinaryBundle::new(bs))
    }

    /// Binary multiplication.
    ///
    /// Returns the lower-order half of the output bits, ie a number with the same number
    /// of bits as the inputs.
    fn bin_multiplication_lower_half(
        &mut self,
        xs: &BinaryBundle<Self::Item>,
        ys: &BinaryBundle<Self::Item>,
    ) -> Result<BinaryBundle<Self::Item>, Self::Error> {
        if xs.moduli() != ys.moduli() {
            return Err(Self::Error::from(FancyError::UnequalModuli));
        }

        let xwires = xs.wires();
        let ywires = ys.wires();

        let mut sum = xwires
            .iter()
            .map(|x| self.and(x, &ywires[0]))
            .collect::<Result<Vec<Self::Item>, Self::Error>>()
            .map(BinaryBundle::new)?;

        for i in 1..xwires.len() {
            let mul = xwires
                .iter()
                .map(|x| self.and(x, &ywires[i]))
                .collect::<Result<Vec<Self::Item>, Self::Error>>()
                .map(BinaryBundle::new)?;
            let shifted = self.shift(&mul, i).map(BinaryBundle)?;
            sum = self.bin_addition_no_carry(&sum, &shifted)?;
        }

        Ok(sum)
    }

    /// Full multiplier
    fn bin_mul(
        &mut self,
        xs: &BinaryBundle<Self::Item>,
        ys: &BinaryBundle<Self::Item>,
    ) -> Result<BinaryBundle<Self::Item>, Self::Error> {
        if xs.moduli() != ys.moduli() {
            return Err(Self::Error::from(FancyError::UnequalModuli));
        }

        let xwires = xs.wires();
        let ywires = ys.wires();

        let mut sum = xwires
            .iter()
            .map(|x| self.and(x, &ywires[0]))
            .collect::<Result<_, _>>()
            .map(BinaryBundle::new)?;

        let zero = self.constant(0, 2)?;
        sum.pad(&zero, 1);

        for i in 1..xwires.len() {
            let mul = xwires
                .iter()
                .map(|x| self.and(x, &ywires[i]))
                .collect::<Result<_, _>>()
                .map(BinaryBundle::new)?;
            let shifted = self.shift_extend(&mul, i).map(BinaryBundle::from)?;
            let res = self.bin_addition(&sum, &shifted)?;
            sum = res.0;
            sum.push(res.1);
        }

        Ok(sum)
    }

    /// Divider
    fn bin_div(
        &mut self,
        xs: &BinaryBundle<Self::Item>,
        ys: &BinaryBundle<Self::Item>,
    ) -> Result<BinaryBundle<Self::Item>, Self::Error> {
        if xs.moduli() != ys.moduli() {
            return Err(Self::Error::from(FancyError::UnequalModuli));
        }
        let ys_neg = self.bin_twos_complement(ys)?;
        let mut acc = self.bin_constant_bundle(0, xs.size())?;
        let mut qs = BinaryBundle::new(Vec::new());
        for x in xs.iter().rev() {
            acc.pop();
            acc.insert(0, x.clone());
            let (res, cout) = self.bin_addition(&acc, &ys_neg)?;
            acc = self.multiplex(&cout, &acc, &res).map(BinaryBundle)?;
            qs.push(cout);
        }
        qs.reverse(); // Switch back to little-endian
        Ok(qs)
    }

    /// Compute the twos complement of the input bundle (which must be base 2).
    fn bin_twos_complement(
        &mut self,
        xs: &BinaryBundle<Self::Item>,
    ) -> Result<BinaryBundle<Self::Item>, Self::Error> {
        let not_xs = xs
            .wires()
            .iter()
            .map(|x| self.negate(x))
            .collect::<Result<Vec<Self::Item>, Self::Error>>()
            .map(BinaryBundle::new)?;
        let one = self.bin_constant_bundle(1, xs.size())?;
        self.bin_addition_no_carry(&not_xs, &one)
    }

    /// Subtract two binary bundles. Returns the result and whether it underflowed.
    ///
    /// Due to the way that `twos_complement(0) = 0`, underflow indicates `y != 0 && x >= y`.
    fn bin_subtraction(
        &mut self,
        xs: &BinaryBundle<Self::Item>,
        ys: &BinaryBundle<Self::Item>,
    ) -> Result<(BinaryBundle<Self::Item>, Self::Item), Self::Error> {
        let neg_ys = self.bin_twos_complement(&ys)?;
        self.bin_addition(&xs, &neg_ys)
    }

    /// If `x=0` return `c1` as a bundle of constant bits, else return `c2`.
    fn bin_multiplex_constant_bits(
        &mut self,
        x: &Self::Item,
        c1: u128,
        c2: u128,
        nbits: usize,
    ) -> Result<BinaryBundle<Self::Item>, Self::Error> {
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
            .map(|(b1, b2)| self.mux_constant_bits(x, b1, b2))
            .collect::<Result<Vec<Self::Item>, Self::Error>>()
            .map(BinaryBundle::new)
    }

    /// Write the constant in binary and that gives you the shift amounts, Eg.. 7x is 4x+2x+x.
    fn bin_cmul(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        c: u128,
        nbits: usize,
    ) -> Result<BinaryBundle<Self::Item>, Self::Error> {
        let zero = self.bin_constant_bundle(0, nbits)?;
        util::u128_to_bits(c, nbits)
            .into_iter()
            .enumerate()
            .filter_map(|(i, b)| if b > 0 { Some(i) } else { None })
            .fold(Ok(zero), |z, shift_amt| {
                let s = self.shift(x, shift_amt).map(BinaryBundle)?;
                self.bin_addition_no_carry(&(z?), &s)
            })
    }

    /// Compute the absolute value of a binary bundle.
    fn bin_abs(
        &mut self,
        x: &BinaryBundle<Self::Item>,
    ) -> Result<BinaryBundle<Self::Item>, Self::Error> {
        let sign = x.wires().last().unwrap();
        let negated = self.bin_twos_complement(x)?;
        self.multiplex(&sign, x, &negated).map(BinaryBundle)
    }

    /// Returns 1 if `x < y`.
    fn bin_lt(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        y: &BinaryBundle<Self::Item>,
    ) -> Result<Self::Item, Self::Error> {
        // underflow indicates y != 0 && x >= y
        // requiring special care to remove the y != 0, which is what follows.
        let (_, lhs) = self.bin_subtraction(x, y)?;

        // Now we build a clause equal to (y == 0 || x >= y), which we can OR with
        // lhs to remove the y==0 aspect.
        // check if y==0
        let y_contains_1 = self.or_many(y.wires())?;
        let y_eq_0 = self.negate(&y_contains_1)?;

        // if x != 0, then x >= y, ... assuming x is not negative
        let x_contains_1 = self.or_many(x.wires())?;

        // y == 0 && x >= y
        let rhs = self.and(&y_eq_0, &x_contains_1)?;

        // (y != 0 && x >= y) || (y == 0 && x >= y)
        // => x >= y && (y != 0 || y == 0)\
        // => x >= y && 1
        // => x >= y
        let geq = self.or(&lhs, &rhs)?;
        self.negate(&geq)
    }

    /// Returns 1 if `x >= y`.
    fn bin_geq(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        y: &BinaryBundle<Self::Item>,
    ) -> Result<Self::Item, Self::Error> {
        let z = self.bin_lt(x, y)?;
        self.negate(&z)
    }

    /// Compute the maximum bundle in `xs`.
    fn bin_max(
        &mut self,
        xs: &[BinaryBundle<Self::Item>],
    ) -> Result<BinaryBundle<Self::Item>, Self::Error> {
        if xs.len() < 2 {
            return Err(Self::Error::from(FancyError::InvalidArgNum {
                got: xs.len(),
                needed: 2,
            }));
        }
        xs.iter().skip(1).fold(Ok(xs[0].clone()), |x, y| {
            x.map(|x| {
                let pos = self.bin_lt(&x, y)?;
                let neg = self.negate(&pos)?;
                x.wires()
                    .iter()
                    .zip(y.wires().iter())
                    .map(|(x, y)| {
                        let xp = self.mul(x, &neg)?;
                        let yp = self.mul(y, &pos)?;
                        self.add(&xp, &yp)
                    })
                    .collect::<Result<Vec<Self::Item>, Self::Error>>()
                    .map(BinaryBundle::new)
            })?
        })
    }

    /// Demux a binary bundle into a unary vector.
    fn bin_demux(&mut self, x: &BinaryBundle<Self::Item>) -> Result<Vec<Self::Item>, Self::Error> {
        let wires = x.wires();
        let nbits = wires.len();
        if nbits > 8 {
            return Err(Self::Error::from(FancyError::InvalidArg(
                "wire bitlength too large".to_string(),
            )));
        }

        let mut outs = Vec::with_capacity(1 << nbits);

        for ix in 0..1 << nbits {
            let mut acc = wires[0].clone();
            if (ix & 1) == 0 {
                acc = self.negate(&acc)?;
            }
            for (i, w) in wires.iter().enumerate().skip(1) {
                if ((ix >> i) & 1) > 0 {
                    acc = self.and(&acc, w)?;
                } else {
                    let not_w = self.negate(w)?;
                    acc = self.and(&acc, &not_w)?;
                }
            }
            outs.push(acc);
        }

        Ok(outs)
    }
}
