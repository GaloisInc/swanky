//! Module containing `BundleGadgets`, which are mostly CRT-based gadgets for Fancy.

use std::ops::Index;

use itertools::Itertools;

use super::{to_vec_option, Fancy, HasModulus};
use crate::error::FancyError;
use crate::util;

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
    pub fn pad(&mut self, val: W) {
        self.0.push(val);
    }

    /// Extract a wire from the Bundle, removing it and returning it.
    pub fn extract(&mut self, wire_index: usize) -> W {
        self.0.remove(wire_index)
    }

    /// Access the underlying iterator
    pub fn iter(&self) -> std::slice::Iter<W> {
        self.0.iter()
    }
}

impl <W: Clone + HasModulus> Index<usize> for Bundle<W> {
    type Output = W;

    fn index(&self, idx: usize) -> &Self::Output {
        self.0.index(idx)
    }
}

/// Extension trait for `Fancy` providing advanced gadgets based on bundles of wires.
pub trait BundleGadgets: Fancy {
    ////////////////////////////////////////////////////////////////////////////////
    // Bundle creation

    /// Crate an input bundle for the garbler using moduli `ps` and optional inputs `xs`.
    fn garbler_input_bundle(
        &mut self,
        ps: &[u16],
        opt_xs: Option<Vec<u16>>,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        let xs = to_vec_option(opt_xs, ps.len());
        ps.iter()
            .zip(xs)
            .map(|(&p, x)| self.garbler_input(p, x))
            .collect::<Result<Vec<Self::Item>, Self::Error>>()
            .map(Bundle)
    }

    /// Crate an input bundle for the evaluator using moduli `ps`.
    fn evaluator_input_bundle(&mut self, ps: &[u16]) -> Result<Bundle<Self::Item>, Self::Error> {
        ps.iter()
            .map(|&p| self.evaluator_input(p))
            .collect::<Result<Vec<Self::Item>, Self::Error>>()
            .map(Bundle)
    }

    /// Crate an input bundle for the garbler using composite CRT modulus `q` and optional
    /// input `x`.
    fn garbler_input_bundle_crt(
        &mut self,
        q: u128,
        opt_x: Option<u128>,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        self.garbler_input_bundle(&util::factor(q), opt_x.map(|x| util::crt_factor(x, q)))
    }

    /// Crate an input bundle for the evaluator using composite CRT modulus `q`.
    fn evaluator_input_bundle_crt(&mut self, q: u128) -> Result<Bundle<Self::Item>, Self::Error> {
        self.evaluator_input_bundle(&util::factor(q))
    }

    /// Create an input bundle for the garbler using `nbits` base 2 inputs and optional input `x`.
    fn garbler_input_bundle_binary(
        &mut self,
        nbits: usize,
        opt_x: Option<u128>,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        self.garbler_input_bundle(&vec![2; nbits], opt_x.map(|x| util::u128_to_bits(x, nbits)))
    }

    /// Create an input bundle for the evaluator using n base 2 inputs.
    fn evaluator_input_bundle_binary(
        &mut self,
        n: usize,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        self.evaluator_input_bundle(&vec![2; n])
    }

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

    /// Creates a bundle of constant wires for the CRT representation of `x` under
    /// composite modulus `q`.
    fn constant_bundle_crt(&mut self, x: u128, q: u128) -> Result<Bundle<Self::Item>, Self::Error> {
        let ps = util::factor(q);
        let xs = ps.iter().map(|&p| (x % p as u128) as u16).collect_vec();
        self.constant_bundle(&xs, &ps)
    }

    /// Create a constant bundle using base 2 inputs.
    fn constant_bundle_binary(
        &mut self,
        val: u128,
        nbits: usize,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        self.constant_bundle(&util::u128_to_bits(val, nbits), &vec![2; nbits])
    }

    /// Create `n` garbler input bundles, using moduli `ps` and optional inputs `xs`.
    fn garbler_input_bundles(
        &mut self,
        ps: &[u16],
        n: usize,
        opt_xs: Option<Vec<Vec<u16>>>,
    ) -> Result<Vec<Bundle<Self::Item>>, Self::Error> {
        if let Some(inps) = opt_xs {
            if inps.len() != n {
                return Err(Self::Error::from(FancyError::InvalidArgNum {
                    got: inps.len(),
                    needed: n,
                }));
            }
            inps.into_iter()
                .map(|xs| self.garbler_input_bundle(ps, Some(xs)))
                .collect()
        } else {
            (0..n)
                .map(|_| self.garbler_input_bundle(ps, None))
                .collect()
        }
    }

    /// Create `n` evaluator input bundles, using moduli `ps`.
    fn evaluator_input_bundles(
        &mut self,
        ps: &[u16],
        n: usize,
    ) -> Result<Vec<Bundle<Self::Item>>, Self::Error> {
        (0..n).map(|_| self.evaluator_input_bundle(ps)).collect()
    }

    /// Create `n` garbler input bundles, under composite CRT modulus `q` and optional
    /// inputs `xs`.
    fn garbler_input_bundles_crt(
        &mut self,
        q: u128,
        n: usize,
        opt_xs: Option<Vec<u128>>,
    ) -> Result<Vec<Bundle<Self::Item>>, Self::Error> {
        if let Some(xs) = opt_xs {
            if xs.len() != n {
                return Err(Self::Error::from(FancyError::InvalidArgNum {
                    got: xs.len(),
                    needed: n,
                }));
            }
            xs.into_iter()
                .map(|x| self.garbler_input_bundle_crt(q, Some(x)))
                .collect()
        } else {
            (0..n)
                .map(|_| self.garbler_input_bundle_crt(q, None))
                .collect()
        }
    }

    /// Create `n` evaluator input bundles, under composite CRT modulus `q`.
    fn evaluator_input_bundles_crt(
        &mut self,
        q: u128,
        n: usize,
    ) -> Result<Vec<Bundle<Self::Item>>, Self::Error> {
        (0..n).map(|_| self.evaluator_input_bundle_crt(q)).collect()
    }

    /// Output the wires that make up a bundle.
    fn output_bundle(&mut self, x: &Bundle<Self::Item>) -> Result<(), Self::Error> {
        for w in x.wires() {
            self.output(w)?;
        }
        Ok(())
    }

    /// Output a slice of bundles.
    fn output_bundles(&mut self, xs: &[Bundle<Self::Item>]) -> Result<(), Self::Error> {
        for x in xs.iter() {
            self.output_bundle(x)?;
        }
        Ok(())
    }

    ////////////////////////////////////////////////////////////////////////////////
    // High-level computations dealing with bundles.

    /// Add two wire bundles, residue by residue.
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
            .map(Bundle)
    }

    /// Subtract two wire bundles, residue by residue.
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
            .map(Bundle)
    }

    /// Multiplies each wire in `x` by the corresponding residue of `c`.
    fn cmul_bundle(
        &mut self,
        x: &Bundle<Self::Item>,
        c: u128,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        let cs = util::crt(c, &x.moduli());
        x.wires()
            .iter()
            .zip(cs.into_iter())
            .map(|(x, c)| self.cmul(x, c))
            .collect::<Result<Vec<Self::Item>, Self::Error>>()
            .map(Bundle)
    }

    /// Multiply `x` with `y`.
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
            .map(Bundle)
    }

    /// Exponentiate `x` by the constant `c`.
    fn cexp_bundle(
        &mut self,
        x: &Bundle<Self::Item>,
        c: u16,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        x.wires()
            .iter()
            .map(|x| {
                let p = x.modulus();
                let tab = (0..p)
                    .map(|x| ((x as u64).pow(c as u32) % p as u64) as u16)
                    .collect_vec();
                self.proj(x, p, Some(tab))
            })
            .collect::<Result<Vec<Self::Item>, Self::Error>>()
            .map(Bundle)
    }

    /// Compute the remainder with respect to modulus `p`.
    fn rem_bundle(
        &mut self,
        x: &Bundle<Self::Item>,
        p: u16,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        let i = x.moduli().iter().position(|&q| p == q).ok_or_else(|| {
            Self::Error::from(FancyError::InvalidArg(
                "p is not a modulus in this bundle!".to_string(),
            ))
        })?;
        let w = &x.wires()[i];
        x.moduli()
            .iter()
            .map(|&q| self.mod_change(w, q))
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

    /// Mixed radix addition.
    fn mixed_radix_addition(
        &mut self,
        xs: &[Bundle<Self::Item>],
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        let nargs = xs.len();
        let n = xs[0].wires().len();

        if nargs < 2 {
            return Err(Self::Error::from(FancyError::InvalidArgNum {
                got: nargs,
                needed: 2,
            }));
        }
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
        let n = xs[0].wires().len();

        if nargs < 2 {
            return Err(Self::Error::from(FancyError::InvalidArgNum {
                got: nargs,
                needed: 2,
            }));
        }
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
            opt_carry = Some(self.proj(&sum_with_carry, next_mod, Some(tt))?);
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
        &mut self,
        bun: &Bundle<Self::Item>,
        ms: &[u16],
    ) -> Result<Self::Item, Self::Error> {
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
                .map(|(i, tt)| self.proj(wire, ms[i], Some(tt)))
                .collect::<Result<Vec<Self::Item>, Self::Error>>()?;

            ds.push(Bundle(new_ds));
        }

        self.mixed_radix_addition_msb_only(&ds)
    }

    /// Compute `max(x,0)`.
    ///
    /// Optional output moduli.
    fn relu(
        &mut self,
        x: &Bundle<Self::Item>,
        accuracy: &str,
        output_moduli: Option<&[u16]>,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        let factors_of_m = &get_ms(x, accuracy);
        let res = self.fractional_mixed_radix(x, factors_of_m)?;

        // project the MSB to 0/1, whether or not it is less than p/2
        let p = *factors_of_m.last().unwrap();
        let mask_tt = (0..p).map(|x| (x < p / 2) as u16).collect_vec();
        let mask = self.proj(&res, 2, Some(mask_tt))?;

        // use the mask to either output x or 0
        output_moduli
            .map(|ps| x.with_moduli(ps))
            .as_ref()
            .unwrap_or(x)
            .wires()
            .iter()
            .map(|x| self.mul(x, &mask))
            .collect::<Result<Vec<Self::Item>, Self::Error>>()
            .map(Bundle)
    }

    /// Return 0 if `x` is positive and 1 if `x` is negative.
    fn sign(&mut self, x: &Bundle<Self::Item>, accuracy: &str) -> Result<Self::Item, Self::Error> {
        let factors_of_m = &get_ms(x, accuracy);
        let res = self.fractional_mixed_radix(x, factors_of_m)?;
        let p = *factors_of_m.last().unwrap();
        let tt = (0..p).map(|x| (x >= p / 2) as u16).collect_vec();
        self.proj(&res, 2, Some(tt))
    }

    /// Return `if x >= 0 then 1 else -1`, where `-1` is interpreted as `Q-1`.
    ///
    /// If provided, will produce a bundle under `output_moduli` instead of `x.moduli()`
    fn sgn(
        &mut self,
        x: &Bundle<Self::Item>,
        accuracy: &str,
        output_moduli: Option<&[u16]>,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        let sign = self.sign(x, accuracy)?;
        output_moduli
            .unwrap_or(&x.moduli())
            .iter()
            .map(|&p| {
                let tt = vec![1, p - 1];
                self.proj(&sign, p, Some(tt))
            })
            .collect::<Result<Vec<Self::Item>, Self::Error>>()
            .map(Bundle)
    }

    /// Returns 1 if `x < y`. Works on both CRT and binary bundles.
    ///
    /// Binary ignores accuracy argument.
    fn lt(
        &mut self,
        x: &Bundle<Self::Item>,
        y: &Bundle<Self::Item>,
        accuracy: &str,
    ) -> Result<Self::Item, Self::Error> {
        if x.is_binary() {
            // underflow indicates y != 0 && x >= y
            // requiring special care to remove the y != 0, which is what follows.
            let (_, lhs) = self.binary_subtraction(x, y)?;

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
        } else {
            let z = self.sub_bundles(x, y)?;
            self.sign(&z, accuracy)
        }
    }

    /// Returns 1 if `x >= y`. Works on both CRT and binary bundles.
    fn geq(
        &mut self,
        x: &Bundle<Self::Item>,
        y: &Bundle<Self::Item>,
        accuracy: &str,
    ) -> Result<Self::Item, Self::Error> {
        let z = self.lt(x, y, accuracy)?;
        self.negate(&z)
    }

    /// Compute the maximum bundle in `xs`.
    fn max(
        &mut self,
        xs: &[Bundle<Self::Item>],
        accuracy: &str,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        if xs.len() < 2 {
            return Err(Self::Error::from(FancyError::InvalidArgNum {
                got: xs.len(),
                needed: 2,
            }));
        }
        xs.iter().skip(1).fold(Ok(xs[0].clone()), |x, y| {
            x.map(|x| {
                let pos = self.lt(&x, y, accuracy)?;
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
                    .map(Bundle)
            })?
        })
    }

    ////////////////////////////////////////////////////////////////////////////////
    // other gadgets

    /// Binary addition. Returns the result and the carry.
    fn binary_addition(
        &mut self,
        xs: &Bundle<Self::Item>,
        ys: &Bundle<Self::Item>,
    ) -> Result<(Bundle<Self::Item>, Self::Item), Self::Error> {
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
        Ok((Bundle(bs), c))
    }

    /// Binary addition. Avoids creating extra gates for the final carry.
    fn binary_addition_no_carry(
        &mut self,
        xs: &Bundle<Self::Item>,
        ys: &Bundle<Self::Item>,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
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
        Ok(Bundle(bs))
    }

    /// Binary multiplication.
    ///
    /// Returns the lower-order half of the output bits, ie a number with the same number
    /// of bits as the inputs.
    fn binary_multiplication_lower_half(
        &mut self,
        xs: &Bundle<Self::Item>,
        ys: &Bundle<Self::Item>,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        if xs.moduli() != ys.moduli() {
            return Err(Self::Error::from(FancyError::UnequalModuli));
        }

        let xwires = xs.wires();
        let ywires = ys.wires();

        let mut sum = xwires
            .iter()
            .map(|x| self.and(x, &ywires[0]))
            .collect::<Result<Vec<Self::Item>, Self::Error>>()
            .map(Bundle)?;

        for i in 1..xwires.len() {
            let mul = xwires
                .iter()
                .map(|x| self.and(x, &ywires[i]))
                .collect::<Result<Vec<Self::Item>, Self::Error>>()
                .map(Bundle)?;
            let shifted = self.shift(&mul, i)?;
            sum = self.binary_addition_no_carry(&sum, &shifted)?;
        }

        Ok(sum)
    }

    /// Compute the twos complement of the input bundle (which must be base 2).
    fn twos_complement(
        &mut self,
        xs: &Bundle<Self::Item>,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        let not_xs = xs
            .wires()
            .iter()
            .map(|x| self.negate(x))
            .collect::<Result<Vec<Self::Item>, Self::Error>>()?;
        let one = self.constant_bundle_binary(1, xs.size())?;
        self.binary_addition_no_carry(&Bundle(not_xs), &one)
    }

    /// Subtract two binary bundles. Returns the result and whether it underflowed.
    ///
    /// Due to the way that `twos_complement(0) = 0`, underflow indicates `y != 0 && x >= y`.
    fn binary_subtraction(
        &mut self,
        xs: &Bundle<Self::Item>,
        ys: &Bundle<Self::Item>,
    ) -> Result<(Bundle<Self::Item>, Self::Item), Self::Error> {
        let neg_ys = self.twos_complement(&ys)?;
        self.binary_addition(&xs, &neg_ys)
    }

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

    /// If `x=0` return `c1` as a bundle of constant bits, else return `c2`.
    fn multiplex_constant_bits(
        &mut self,
        x: &Self::Item,
        c1: u128,
        c2: u128,
        nbits: usize,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
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
            .map(Bundle)
    }

    /// Shift residues, replacing them with zeros in the modulus of the least signifigant residue.
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

    /// Write the constant in binary and that gives you the shift amounts, Eg.. 7x is 4x+2x+x.
    fn binary_cmul(
        &mut self,
        x: &Bundle<Self::Item>,
        c: u128,
        nbits: usize,
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        if !x.is_binary() {
            return Err(Self::Error::from(FancyError::ArgNotBinary));
        }
        let zero = self.constant_bundle(&vec![0; nbits], &vec![2; nbits])?;
        util::u128_to_bits(c, nbits)
            .into_iter()
            .enumerate()
            .filter_map(|(i, b)| if b > 0 { Some(i) } else { None })
            .fold(Ok(zero), |z, shift_amt| {
                let s = self.shift(x, shift_amt)?;
                self.binary_addition_no_carry(&(z?), &s)
            })
    }

    /// Compute the absolute value of a binary bundle.
    fn abs(&mut self, x: &Bundle<Self::Item>) -> Result<Bundle<Self::Item>, Self::Error> {
        if !x.is_binary() {
            return Err(Self::Error::from(FancyError::ArgNotBinary));
        }
        let sign = x.wires().last().unwrap();
        let negated = self.twos_complement(x)?;
        self.multiplex(&sign, x, &negated)
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
