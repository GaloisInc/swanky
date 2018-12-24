//! The `Fancy` trait represents the kinds of computations possible in `fancy-garbling`.
//!
//! An implementer must be able to create inputs, constants, do modular arithmetic, and
//! create projections.

use itertools::Itertools;
use crate::util;

/// An object that knows its own modulus.
pub trait HasModulus {
    /// The modulus of the wire.
    fn modulus(&self) -> u16;
}

/// A collection of wires, useful for the garbled gadgets defined by `BundleGadgets`.
pub struct Bundle<W: HasModulus>(Vec<W>);

impl <W: HasModulus> Bundle<W> {
    /// Return the moduli of all the wires in the bundle.
    pub fn moduli(&self) -> Vec<u16> {
        self.0.iter().map(|w| w.modulus()).collect()
    }

    /// Extract the wires from this bundle.
    pub fn wires(&self) -> &[W] {
        &self.0
    }
}

/// DSL for the basic computations supported by fancy-garbling.
pub trait Fancy {
    /// The underlying wire datatype created by an object implementing `Fancy`.
    type Wire: Clone + HasModulus;

    /// Create an input for the garbler with modulus `q`.
    fn garbler_input(&mut self, q: u16) -> Self::Wire;

    /// Create an input for the evaluator with modulus `q`.
    fn evaluator_input(&mut self, q: u16) -> Self::Wire;

    /// Create a constant `x` with modulus `q`.
    fn constant(&mut self, x: u16, q: u16) -> Self::Wire;

    /// Add `x` and `y`.
    fn add(&mut self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire;

    /// Subtract `x` and `y`.
    fn sub(&mut self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire;

    /// Multiply `x` and `y`.
    fn mul(&mut self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire;

    /// Multiply `x` times the constant `c`.
    fn cmul(&mut self, x: &Self::Wire, c: u16) -> Self::Wire;

    /// Project `x` according to the truth table `tt`. Resulting wire has modulus `q`.
    fn proj(&mut self, x: &Self::Wire, q: u16, tt: Vec<u16>) -> Self::Wire;

    ////////////////////////////////////////////////////////////////////////////////
    // Functions built on top of basic fancy operations.

    /// Create `n` garbler inputs with modulus `q`.
    fn garbler_inputs(&mut self, q: u16, n: usize) -> Vec<Self::Wire> {
        (0..n).map(|_| self.garbler_input(q)).collect()
    }

    /// Create `n` evaluator inputs with modulus `q`.
    fn evaluator_inputs(&mut self, q: u16, n: usize) -> Vec<Self::Wire> {
        (0..n).map(|_| self.evaluator_input(q)).collect()
    }

    /// Sum up a slice of wires.
    fn add_many(&mut self, args: &[Self::Wire]) -> Self::Wire {
        assert!(args.len() > 1);
        let mut z = args[0].clone();
        for x in args.iter().skip(1) {
            z = self.add(&z,&x);
        }
        z
    }

    /// Xor is just addition, with the requirement that `x` and `y` are mod 2.
    fn xor(&mut self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        assert!(x.modulus() == 2 && y.modulus() == 2);
        self.add(x,y)
    }

    /// Negate by xoring `x` with `1`.
    fn negate(&mut self, x: &Self::Wire) -> Self::Wire {
        assert_eq!(x.modulus(), 2);
        let one = self.constant(1,2);
        self.xor(x, &one)
    }

    /// And is just multiplication, with the requirement that `x` and `y` are mod 2.
    fn and(&mut self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        assert!(x.modulus() == 2 && y.modulus() == 2);
        self.mul(x,y)
    }

    /// Or uses Demorgan's Rule implemented with multiplication and negation.
    fn or(&mut self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        assert!(x.modulus() == 2 && y.modulus() == 2);
        let notx = self.negate(x);
        let noty = self.negate(y);
        let z = self.and(&notx, &noty);
        self.negate(&z)
    }

    /// Returns 1 if all wires equal 1.
    fn and_many(&mut self, args: &[Self::Wire]) -> Self::Wire {
        args.iter().skip(1).fold(args[0].clone(), |acc, x| self.and(&acc, x))
    }

    /// Returns 1 if any wire equals 1.
    fn or_many(&mut self, args: &[Self::Wire]) -> Self::Wire {
        args.iter().skip(1).fold(args[0].clone(), |acc, x| self.or(&acc, x))
    }

    /// Change the modulus of `x` to `to_modulus` using a projection gate.
    fn mod_change(&mut self, x: &Self::Wire, to_modulus: u16) -> Self::Wire {
        let from_modulus = x.modulus();
        if from_modulus == to_modulus {
            return x.clone();
        }
        let tab = (0..from_modulus).map(|x| x % to_modulus).collect();
        self.proj(x, to_modulus, tab)
    }
}

/// Extension trait for `Fancy` providing advanced gadgets based on bundles of wires.
pub trait BundleGadgets: Fancy {
    ////////////////////////////////////////////////////////////////////////////////
    // Bundle creation

    /// Crate an input bundle for the garbler using moduli `ps`.
    fn garbler_input_bundle(&mut self, ps: &[u16]) -> Bundle<Self::Wire> {
        Bundle(ps.iter().map(|&p| self.garbler_input(p)).collect())
    }

    /// Crate an input bundle for the evaluator using moduli `ps`.
    fn evaluator_input_bundle(&mut self, ps: &[u16]) -> Bundle<Self::Wire> {
        Bundle(ps.iter().map(|&p| self.evaluator_input(p)).collect())
    }

    /// Crate an input bundle for the garbler using composite CRT modulus `q`.
    fn garbler_input_bundle_crt(&mut self, q: u128) -> Bundle<Self::Wire> {
        self.garbler_input_bundle(&util::factor(q))
    }

    /// Crate an input bundle for the evaluator using composite CRT modulus `q`.
    fn evaluator_input_bundle_crt(&mut self, q: u128) -> Bundle<Self::Wire> {
        self.evaluator_input_bundle(&util::factor(q))
    }

    /// Creates a bundle of constant wires using moduli `ps`.
    fn constant_bundle(&mut self, xs: &[u16], ps: &[u16]) -> Bundle<Self::Wire> {
        Bundle(xs.iter().zip(ps.iter()).map(|(&x,&p)| self.constant(x,p)).collect())
    }

    /// Creates a bundle of constant wires for the CRT representation of `x` under
    /// composite modulus `q`.
    fn constant_bundle_crt(&mut self, x: u128, q: u128) -> Bundle<Self::Wire> {
        let ps = util::factor(q);
        let xs = ps.iter().map(|&p| (x % p as u128) as u16).collect_vec();
        self.constant_bundle(&xs,&ps)
    }

    /// Create `n` garbler input bundles, using moduli `ps`.
    fn garbler_input_bundles(&mut self, ps: &[u16], n: usize) -> Vec<Bundle<Self::Wire>> {
        (0..n).map(|_| self.garbler_input_bundle(ps)).collect()
    }

    /// Create `n` evaluator input bundles, using moduli `ps`.
    fn evaluator_input_bundles(&mut self, ps: &[u16], n: usize) -> Vec<Bundle<Self::Wire>> {
        (0..n).map(|_| self.evaluator_input_bundle(ps)).collect()
    }

    /// Create `n` garbler input bundles, under composite CRT modulus `q`.
    fn garbler_input_bundles_crt(&mut self, q: u128, n: usize) -> Vec<Bundle<Self::Wire>> {
        (0..n).map(|_| self.garbler_input_bundle_crt(q)).collect()
    }

    /// Create `n` evaluator input bundles, under composite CRT modulus `q`.
    fn evaluator_input_bundles_crt(&mut self, q: u128, n: usize) -> Vec<Bundle<Self::Wire>> {
        (0..n).map(|_| self.evaluator_input_bundle_crt(q)).collect()
    }

    ////////////////////////////////////////////////////////////////////////////////
    // High-level computations dealing with bundles.

    /// Add two wire bundles, residue by residue.
    fn add_bundles(&mut self, x: &Bundle<Self::Wire>, y: &Bundle<Self::Wire>)
        -> Bundle<Self::Wire> {
        assert_eq!(x.wires().len(), y.wires().len());
        let res = x.wires().iter().zip(y.wires().iter()).map(|(x,y)| self.add(x,y)).collect();
        Bundle(res)
    }

    /// Subtract two wire bundles, residue by residue.
    fn sub_bundles(&mut self, x: &Bundle<Self::Wire>, y: &Bundle<Self::Wire>)
        -> Bundle<Self::Wire> {
        assert_eq!(x.wires().len(), y.wires().len());
        let res = x.wires().iter().zip(y.wires().iter()).map(|(x,y)| self.sub(x,y)).collect();
        Bundle(res)
    }

    /// Multiplies each wire in `x` by the corresponding residue of `c`.
    fn cmul_bundle(&mut self, x: &Bundle<Self::Wire>, c: u128) -> Bundle<Self::Wire> {
        let cs = util::crt(&x.moduli(), c);
        let ws = x.wires().iter().zip(cs.into_iter()).map(|(x,c)| self.cmul(x,c)).collect();
        Bundle(ws)
    }

    /// Multiply `x` with `y`.
    fn mul_bundles(&mut self, x: &Bundle<Self::Wire>, y: &Bundle<Self::Wire>) -> Bundle<Self::Wire> {
        Bundle(x.wires().iter().zip(y.wires().iter()).map(|(x,y)| self.mul(x,y)).collect())
    }

    /// Divide `x` by the constant `c`. Somewhat finicky, please test. I believe that it
    /// requires that `c` is coprime with all moduli.
    fn cdiv_bundle(&mut self, x: &Bundle<Self::Wire>, c: u16) -> Bundle<Self::Wire> {
        Bundle(x.wires().iter().map(|x| {
            let p = x.modulus();
            if c % p == 0 {
                self.cmul(x,0)
            } else {
                let d = util::inv(c as i16, p as i16) as u16;
                self.cmul(x,d)
            }
        }).collect())
    }

    /// Exponentiate `x` by the constant `c`.
    fn cexp_bundle(&mut self, x: &Bundle<Self::Wire>, c: u16) -> Bundle<Self::Wire> {
        Bundle(x.wires().iter().map(|x| {
            let p = x.modulus();
            let tab = (0..p).map(|x| {
                ((x as u64).pow(c as u32) % p as u64) as u16
            }).collect();
            self.proj(x, p, tab)
        }).collect())
    }

    /// Compute the remainder with respect to modulus `p`.
    fn rem_bundle(&mut self, x: &Bundle<Self::Wire>, p: u16) -> Bundle<Self::Wire> {
        let i = x.moduli().iter().position(|&q| p == q).expect("p is not a moduli in this bundle!");
        let w = &x.wires()[i];
        Bundle(x.moduli().iter().map(|&q| self.mod_change(w,q)).collect())
    }

    /// Compute `x == y`. Returns a wire encoding the result mod 2.
    fn eq_bundles(&mut self, x: &Bundle<Self::Wire>, y: &Bundle<Self::Wire>) -> Self::Wire {
        assert_eq!(x.moduli(), y.moduli());
        let wlen = x.wires().len() as u16;
        let zs = x.wires().iter().zip_eq(y.wires().iter()).map(|(x,y)| {
            // compute (x-y == 0) for each residue
            let z = self.sub(x,y);
            let mut eq_zero_tab = vec![0; x.modulus() as usize];
            eq_zero_tab[0] = 1;
            self.proj(&z, wlen + 1, eq_zero_tab)
        }).collect_vec();
        // add up the results, and output whether they equal zero or not, mod 2
        let z = self.add_many(&zs);
        let b = zs.len();
        let mut tab = vec![0;b+1];
        tab[b] = 1;
        self.proj(&z, 2, tab)
    }

    /// Mixed radix addition.
    fn mixed_radix_addition(&mut self, xs: &[Bundle<Self::Wire>]) -> Bundle<Self::Wire> {
        let nargs = xs.len();
        let n = xs[0].wires().len();
        assert!(xs.len() > 1 && xs.iter().all(|x| x.wires().len() == n));

        let mut digit_carry = None;
        let mut carry_carry = None;
        let mut max_carry = 0;

        let mut res = Vec::with_capacity(n);

        for i in 0..n {
            // all the ith digits, in one vec
            let ds = xs.iter().map(|x| x.wires()[i].clone()).collect_vec();

            // compute the digit -- easy
            let digit_sum = self.add_many(&ds);
            let digit = digit_carry.map_or(digit_sum.clone(), |d| self.add(&digit_sum, &d));

            if i < n-1 {
                // compute the carries
                let q = xs[0].wires()[i].modulus();
                // max_carry currently contains the max carry from the previous iteration
                let max_val = nargs as u16 * (q-1) + max_carry;
                // now it is the max carry of this iteration
                max_carry = max_val / q;

                let modded_ds = ds.iter().map(|d| self.mod_change(d, max_val+1)).collect_vec();

                let carry_sum = self.add_many(&modded_ds);
                // add in the carry from the previous iteration
                let carry = carry_carry.map_or(carry_sum.clone(), |c| self.add(&carry_sum, &c));

                // carry now contains the carry information, we just have to project it to
                // the correct moduli for the next iteration
                let next_mod = xs[0].wires()[i+1].modulus();
                let tt = (0..=max_val).map(|i| (i / q) % next_mod).collect_vec();
                digit_carry = Some(self.proj(&carry, next_mod, tt));

                let next_max_val = nargs as u16 * (next_mod - 1) + max_carry;

                if i < n-2 {
                    if max_carry < next_mod {
                        carry_carry = Some(self.mod_change(digit_carry.as_ref().unwrap(), next_max_val + 1));
                    } else {
                        let tt = (0..=max_val).map(|i| i / q).collect_vec();
                        carry_carry = Some(self.proj(&carry, next_max_val + 1, tt));
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
        Bundle(res)
    }

    ////////////////////////////////////////////////////////////////////////////////
    // Fancy functions based on Mike's fractional mixed radix trick.

    fn fractional_mixed_radix(&mut self, bun: &Bundle<Self::Wire>, factors_of_m: &[u16]) -> Bundle<Self::Wire> {
        let ndigits = factors_of_m.len();

        let q = util::product(&bun.moduli());
        let M = util::product(factors_of_m);

        let mut ds = Vec::new();

        for wire in bun.wires().iter() {
            let p = wire.modulus();

            let mut tabs = vec![Vec::with_capacity(p as usize); ndigits];

            for x in 0..p {
                let crt_coef = util::inv(((q / p as u128) % p as u128) as i64, p as i64);
                let y = (M as f64 * x as f64 * crt_coef as f64 / p as f64).round() as u128 % M;
                let digits = util::as_mixed_radix(y, factors_of_m);
                for i in 0..ndigits {
                    tabs[i].push(digits[i]);
                }
            }

            let new_ds = tabs.into_iter().enumerate()
                .map(|(i,tt)| self.proj(wire, factors_of_m[i], tt))
                .collect_vec();

            ds.push(Bundle(new_ds));
        }

        self.mixed_radix_addition(&ds)
    }

    // pub fn relu(&mut self, xbun: BundleRef, factors_of_m: &[u16]) -> BundleRef {
    //     let res = self.fractional_mixed_radix(xbun, factors_of_m);

    //     // project the MSB to 0/1, whether or not it is less than p/2
    //     let p = *factors_of_m.last().unwrap();
    //     let mask_tt = (0..p).map(|x| (x < p/2) as u16).collect();
    //     let mask = self.borrow_mut_builder().proj(*res.last().unwrap(), 2, mask_tt);

    //     // use the mask to either output x or 0
    //     let zwires = self.wires(xbun).into_iter().map(|x| {
    //         self.borrow_mut_builder().half_gate(x,mask)
    //     }).collect_vec();

    //     let primes = self.primes(xbun);
    //     self.add_bundle(zwires, primes)
    // }

    // // outputs 0/1
    // pub fn sign(&mut self, xbun: BundleRef, factors_of_m: &[u16]) -> Ref {
    //     let res = self.fractional_mixed_radix(xbun, factors_of_m);
    //     let p = *factors_of_m.last().unwrap();
    //     let tt = (0..p).map(|x| (x >= p/2) as u16).collect();
    //     self.borrow_mut_builder().proj(*res.last().unwrap(), 2, tt)
    // }

    // // outputs 1/-1
    // pub fn sgn(&mut self, xbun: BundleRef, factors_of_m: &[u16]) -> BundleRef {
    //     let sign = self.sign(xbun, factors_of_m);

    //     let ps = self.primes(xbun);
    //     let q = util::product(&ps);
    //     let mut ws = Vec::with_capacity(ps.len());

    //     for &p in ps.iter() {
    //         let tt = vec![ 1, ((q-1) % p as u128) as u16 ];
    //         let w = self.borrow_mut_builder().proj(sign, p, tt);
    //         ws.push(w);
    //     }
    //     self.add_bundle(ws, ps)
    // }

    // fn exact_ms(&self, xbun: BundleRef) -> Vec<u16> {
    //     match self.primes(xbun).len() {
    //         3 => vec![2;5],
    //         4 => vec![3,26],
    //         5 => vec![3,4,54],
    //         6 => vec![5,5,6,50],
    //         7 => vec![6,6,7,7,74],
    //         8 => vec![5,7,8,8,9,98],
    //         9 => vec![4,7,10,10,10,10,134],
    //         n => panic!("unknown exact Ms for {} primes!", n),
    //     }
    // }

    // pub fn exact_sgn(&mut self, xbun: BundleRef) -> BundleRef {
    //     let ms = self.exact_ms(xbun);
    //     self.sgn(xbun, &ms)
    // }

    // pub fn exact_relu(&mut self, xbun: BundleRef) -> BundleRef {
    //     let ms = self.exact_ms(xbun);
    //     self.relu(xbun, &ms)
    // }

    // pub fn exact_leq(&mut self, xbun: BundleRef, ybun: BundleRef) -> Ref {
    //     let ms = self.exact_ms(xbun);
    //     let zbun = self.sub(xbun, ybun);
    //     self.sign(zbun, &ms)
    // }

    // pub fn max(&mut self, buns: &[BundleRef]) -> BundleRef {
    //     debug_assert!(buns.len() > 1);

    //     buns.iter().skip(1).fold(buns[0], |xbun, &ybun| {
    //         let pos = self.exact_leq(xbun,ybun);
    //         let neg = self.borrow_mut_builder().negate(&pos);

    //         let x_wires = self.wires(xbun);
    //         let y_wires = self.wires(ybun);

    //         let z_wires = x_wires.iter().zip(y_wires.iter()).map(|(&x,&y)| {
    //             let xp = self.borrow_mut_builder().half_gate(x,neg);
    //             let yp = self.borrow_mut_builder().half_gate(y,pos);
    //             self.borrow_mut_builder().add(xp,yp)
    //         }).collect();

    //         let primes = self.primes(xbun);
    //         self.add_bundle(z_wires, primes)
    //     })
    // }
}
