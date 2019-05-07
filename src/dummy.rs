//! Dummy implementation of `Fancy`.
//!
//! Useful for evaluating the circuits produced by `Fancy` without actually
//! creating any circuits.

use crate::error::{DummyError, FancyError};
use crate::fancy::{Fancy, HasModulus};

/// Simple struct that performs the fancy computation over `u16`.
pub struct Dummy {
    outputs: Vec<u16>,
    garbler_inputs: Vec<u16>,
    evaluator_inputs: Vec<u16>,
}

/// Wrapper around `u16`.
#[derive(Clone, Debug)]
pub struct DummyVal {
    val: u16,
    modulus: u16,
}

impl HasModulus for DummyVal {
    fn modulus(&self) -> u16 {
        self.modulus
    }
}

impl Dummy {
    /// Create a new Dummy.
    pub fn new(garbler_inputs: &[u16], evaluator_inputs: &[u16]) -> Dummy {
        Dummy {
            garbler_inputs: garbler_inputs.to_vec(),
            evaluator_inputs: evaluator_inputs.to_vec(),
            outputs: Vec::new(),
        }
    }

    /// Get the output from the fancy computation, consuming the Dummy.
    pub fn get_output(self) -> Vec<u16> {
        self.outputs
    }
}

impl Fancy for Dummy {
    type Item = DummyVal;
    type Error = DummyError;

    fn init(
        &mut self,
        garbler_input_moduli: &[u16],
        evaluator_input_moduli: &[u16],
        reused_deltas: &[Self::Item],
    ) -> Result<(Vec<Self::Item>, Vec<Self::Item>), Self::Error> {
        unimplemented!()
    }

    fn constant(&mut self, val: u16, modulus: u16) -> Result<DummyVal, Self::Error> {
        Ok(DummyVal { val, modulus })
    }

    fn add(&mut self, x: &DummyVal, y: &DummyVal) -> Result<DummyVal, Self::Error> {
        if x.modulus() != y.modulus() {
            return Err(Self::Error::from(FancyError::UnequalModuli));
        }
        Ok(DummyVal {
            val: (x.val + y.val) % x.modulus,
            modulus: x.modulus,
        })
    }

    fn sub(&mut self, x: &DummyVal, y: &DummyVal) -> Result<DummyVal, Self::Error> {
        if x.modulus() != y.modulus() {
            return Err(Self::Error::from(FancyError::UnequalModuli));
        }
        Ok(DummyVal {
            val: (x.modulus + x.val - y.val) % x.modulus,
            modulus: x.modulus,
        })
    }

    fn cmul(&mut self, x: &DummyVal, c: u16) -> Result<DummyVal, Self::Error> {
        Ok(DummyVal {
            val: (x.val * c) % x.modulus,
            modulus: x.modulus,
        })
    }

    fn mul(&mut self, x: &DummyVal, y: &DummyVal) -> Result<DummyVal, Self::Error> {
        Ok(DummyVal {
            val: x.val * y.val % x.modulus,
            modulus: x.modulus,
        })
    }

    fn proj(
        &mut self,
        x: &DummyVal,
        modulus: u16,
        tt: Option<Vec<u16>>,
    ) -> Result<DummyVal, Self::Error> {
        let tt = tt.ok_or_else(|| Self::Error::from(FancyError::NoTruthTable))?;
        if tt.len() < x.modulus() as usize || !tt.iter().all(|&x| x < modulus) {
            return Err(Self::Error::from(FancyError::InvalidTruthTable));
        }
        let val = tt[x.val as usize];
        Ok(DummyVal { val, modulus })
    }

    fn output(&mut self, x: &DummyVal) -> Result<(), Self::Error> {
        self.outputs.push(x.val);
        Ok(())
    }
}

#[cfg(test)]
mod bundle {
    use super::*;
    use crate::fancy::{BinaryGadgets, BundleGadgets, CrtGadgets};
    use crate::util::{self, crt_factor, crt_inv_factor, RngExt};
    use itertools::Itertools;
    use rand::thread_rng;

    const NITERS: usize = 1 << 10;

    #[test] // bundle addition {{{
    fn test_addition() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let q = rng.gen_usable_composite_modulus();
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut d = Dummy::new(&crt_factor(x, q), &crt_factor(y, q));
            {
                let (xs, ys) = d.crt_init(&[q], &[q], &[]).unwrap();
                let z = d.crt_add(&xs[0], &ys[0]).unwrap();
                d.output_bundle(&z).unwrap();
            }
            let z = crt_inv_factor(&d.get_output(), q);
            assert_eq!(z, (x + y) % q);
        }
    }
    //}}}
    #[test] // bundle subtraction {{{
    fn test_subtraction() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let q = rng.gen_usable_composite_modulus();
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut d = Dummy::new(&crt_factor(x, q), &crt_factor(y, q));
            {
                let (xs, ys) = d.crt_init(&[q], &[q], &[]).unwrap();
                let z = d.sub_bundles(&xs[0], &ys[0]).unwrap();
                d.output_bundle(&z).unwrap();
            }
            let z = crt_inv_factor(&d.get_output(), q);
            assert_eq!(z, (x + q - y) % q);
        }
    }
    //}}}
    #[test] // binary cmul {{{
    fn test_binary_cmul() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let nbits = 64;
            let q = 1 << nbits;
            let x = rng.gen_u128() % q;
            let c = 1 + rng.gen_u128() % q;
            let mut d = Dummy::new(&util::u128_to_bits(x, nbits), &[]);
            {
                let (xs, _) = d.bin_init(&[nbits], &[], &[]).unwrap();
                let z = d.bin_cmul(&xs[0], c, nbits).unwrap();
                d.output_bundle(&z).unwrap();
            }
            let z = util::u128_from_bits(&d.get_output());
            assert_eq!(z, (x * c) % q);
        }
    }
    //}}}
    #[test] // binary multiplication {{{
    fn test_binary_multiplication() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let nbits = 64;
            let q = 1 << nbits;
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut d = Dummy::new(&util::u128_to_bits(x, nbits), &util::u128_to_bits(y, nbits));
            {
                let (xs, ys) = d.bin_init(&[nbits], &[nbits], &[]).unwrap();
                let z = d.bin_multiplication_lower_half(&xs[0], &ys[0]).unwrap();
                d.output_bundle(&z).unwrap();
            }
            let z = util::u128_from_bits(&d.get_output());
            assert_eq!(z, (x * y) & (q - 1));
        }
    }
    //}}}
    #[test] // bundle max {{{
    fn max() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);
        let n = 10;
        for _ in 0..NITERS {
            let inps = (0..n).map(|_| rng.gen_u128() % (q / 2)).collect_vec();
            let should_be = *inps.iter().max().unwrap();
            let enc_inps = inps
                .into_iter()
                .flat_map(|x| crt_factor(x, q))
                .collect_vec();
            let mut d = Dummy::new(&enc_inps, &[]);
            {
                let (xs, _) = d
                    .crt_init(&itertools::repeat_n(q, n).collect_vec(), &[], &[])
                    .unwrap();
                let z = d.crt_max(&xs, "100%").unwrap();
                d.output_bundle(&z).unwrap();
            }
            let z = crt_inv_factor(&d.get_output(), q);
            assert_eq!(z, should_be);
        }
    }
    //}}}
    #[test] // twos complement {{{
    fn twos_complement() {
        let mut rng = thread_rng();
        let nbits = 16;
        let q = 1 << nbits;
        for _ in 0..NITERS {
            let x = rng.gen_u128() % q;
            let should_be = (!x + 1) % q;
            let mut d = Dummy::new(&util::u128_to_bits(x, nbits), &[]);
            {
                let (xs, _) = d.bin_init(&[nbits], &[], &[]).unwrap();
                let y = d.bin_twos_complement(&xs[0]).unwrap();
                d.output_bundle(&y).unwrap();
            }
            let outs = d.get_output();
            let y = util::u128_from_bits(&outs);
            assert_eq!(y, should_be, "x={} y={} should_be={}", x, y, should_be);
        }
    }
    //}}}
    #[test] // binary addition {{{
    fn binary_addition() {
        let mut rng = thread_rng();
        let nbits = 16;
        let q = 1 << nbits;
        for _ in 0..NITERS {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let should_be = (x + y) % q;
            let enc_inps = [x, y]
                .into_iter()
                .flat_map(|&x| util::u128_to_bits(x, nbits))
                .collect_vec();
            let mut d = Dummy::new(&enc_inps, &[]);
            {
                let (xs, ys) = d.bin_init(&[nbits], &[nbits], &[]).unwrap();
                let (z, overflow) = d.bin_addition(&xs[0], &ys[0]).unwrap();
                d.output(&overflow).unwrap();
                d.output_bundle(&z).unwrap();
            }
            let outs = d.get_output();
            let overflow = outs[0] > 0;
            let z = util::u128_from_bits(&outs[1..]);
            assert_eq!(
                z, should_be,
                "x={} y={} z={} should_be={}",
                x, y, z, should_be
            );
            assert_eq!(overflow, x + y >= q, "x={} y={}", x, y);
        }
    }
    //}}}
    #[test] // binary subtraction {{{
    fn binary_subtraction() {
        let mut rng = thread_rng();
        let nbits = 16;
        let q = 1 << nbits;
        for _ in 0..NITERS {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let should_be = (x - y) % q;
            let enc_inps = [x, y]
                .into_iter()
                .flat_map(|&x| util::u128_to_bits(x, nbits))
                .collect_vec();
            let mut d = Dummy::new(&enc_inps, &[]);
            {
                let (xs, ys) = d.bin_init(&[nbits], &[nbits], &[]).unwrap();
                let (z, overflow) = d.bin_subtraction(&xs[0], &ys[0]).unwrap();
                d.output(&overflow).unwrap();
                d.output_bundle(&z).unwrap();
            }
            let outs = d.get_output();
            let overflow = outs[0] > 0;
            let z = util::u128_from_bits(&outs[1..]);
            assert_eq!(
                z, should_be,
                "x={} y={} z={} should_be={}",
                x, y, z, should_be
            );
            assert_eq!(overflow, (y != 0 && x >= y), "x={} y={}", x, y);
        }
    }
    //}}}
    #[test] // binary lt {{{
    fn binary_lt() {
        let mut rng = thread_rng();
        let nbits = 16;
        let q = 1 << nbits;
        for _ in 0..NITERS {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let should_be = x < y;
            let enc_inps = [x, y]
                .into_iter()
                .flat_map(|&x| util::u128_to_bits(x, nbits))
                .collect_vec();
            let mut d = Dummy::new(&enc_inps, &[]);
            {
                let (xs, ys) = d.bin_init(&[nbits], &[nbits], &[]).unwrap();
                let z = d.bin_lt(&xs[0], &ys[0]).unwrap();
                d.output(&z).unwrap();
            }
            let z = d.get_output()[0] > 0;
            assert_eq!(z, should_be, "x={} y={}", x, y);
        }
    }
    //}}}
    #[test] // binary max {{{
    fn binary_max() {
        let mut rng = thread_rng();
        let n = 10;
        let nbits = 16;
        let q = 1 << nbits;
        for _ in 0..NITERS {
            let inps = (0..n).map(|_| rng.gen_u128() % q).collect_vec();
            let should_be = *inps.iter().max().unwrap();
            let enc_inps = inps
                .into_iter()
                .flat_map(|x| util::u128_to_bits(x, nbits))
                .collect_vec();
            let mut d = Dummy::new(&enc_inps, &[]);
            {
                let (xs, _) = d
                    .bin_init(&itertools::repeat_n(nbits, n).collect_vec(), &[], &[])
                    .unwrap();
                let z = d.bin_max(&xs).unwrap();
                d.output_bundle(&z).unwrap();
            }
            let z = util::u128_from_bits(&d.get_output());
            assert_eq!(z, should_be);
        }
    }
    //}}}
    #[test] // bundle relu {{{
    fn test_relu() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let q = crate::util::modulus_with_nprimes(4 + rng.gen_usize() % 7); // exact relu supports up to 11 primes
            let x = rng.gen_u128() % q;
            let mut d = Dummy::new(&crt_factor(x, q), &[]);
            {
                let (xs, _) = d.crt_init(&[q], &[], &[]).unwrap();
                let z = d.crt_relu(&xs[0], "100%", None).unwrap();
                d.output_bundle(&z).unwrap();
            }
            let z = crt_inv_factor(&d.get_output(), q);
            if x >= q / 2 {
                assert_eq!(z, 0);
            } else {
                assert_eq!(z, x);
            }
        }
    }
    //}}}
    #[test] // abs {{{
    fn binary_abs() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let nbits = 64;
            let q = 1 << nbits;
            let x = rng.gen_u128() % q;
            let mut d = Dummy::new(&util::u128_to_bits(x, nbits), &[]);
            {
                let (xs, _) = d.bin_init(&[nbits], &[], &[]).unwrap();
                let z = d.bin_abs(&xs[0]).unwrap();
                d.output_bundle(&z).unwrap();
            }
            let z = util::u128_from_bits(&d.get_output());
            let should_be = if x >> (nbits - 1) > 0 {
                ((!x) + 1) & ((1 << nbits) - 1)
            } else {
                x
            };
            assert_eq!(z, should_be);
        }
    }
    //}}}
    #[test] // bundle mixed_radix_addition MSB {{{
    fn test_mixed_radix_addition_msb_only() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let nargs = 2 + rng.gen_usize() % 10;
            let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec();
            let Q: u128 = util::product(&mods);

            println!("nargs={} mods={:?} Q={}", nargs, mods, Q);

            // test maximum overflow
            let mut ds = Vec::new();
            for _ in 0..nargs {
                ds.extend(util::as_mixed_radix(Q - 1, &mods).iter());
            }

            let mut b = Dummy::new(&ds, &[]);
            let (xs, _) = b
                .init_bundles(&itertools::repeat_n(mods.clone(), nargs).collect_vec(), &[], &[])
                .unwrap();
            let z = b.mixed_radix_addition_msb_only(&xs).unwrap();
            b.output(&z).unwrap();
            let res = b.get_output()[0];

            let should_be = *util::as_mixed_radix((Q - 1) * (nargs as u128) % Q, &mods)
                .last()
                .unwrap();
            assert_eq!(res, should_be);

            // test random values
            for _ in 0..4 {
                let mut sum = 0;
                let mut ds = Vec::new();
                for _ in 0..nargs {
                    let x = rng.gen_u128() % Q;
                    sum = (sum + x) % Q;
                    ds.extend(util::as_mixed_radix(x, &mods).iter());
                }

                let mut b = Dummy::new(&ds, &[]);
                let (xs, _) = b
                    .init_bundles(&itertools::repeat_n(mods.clone(), nargs).collect_vec(), &[], &[])
                    .unwrap();
                let z = b.mixed_radix_addition_msb_only(&xs).unwrap();
                b.output(&z).unwrap();
                let res = b.get_output()[0];

                let should_be = *util::as_mixed_radix(sum, &mods).last().unwrap();
                assert_eq!(res, should_be);
            }
        }
    }
    //}}}
}
