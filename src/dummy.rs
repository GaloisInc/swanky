//! Dummy implementation of `Fancy`.
//!
//! Useful for evaluating the circuits produced by `Fancy` without actually
//! creating any circuits.

use crate::error::{DummyError, FancyError};
use crate::fancy::{Fancy, FancyInput, HasModulus};

/// Simple struct that performs the fancy computation over `u16`.
pub struct Dummy {
    outputs: Vec<u16>,
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

impl DummyVal {
    /// Create a new DummyVal.
    pub fn new(val: u16, modulus: u16) -> Self {
        Self { val, modulus }
    }

    /// Extract the value.
    pub fn val(&self) -> u16 {
        self.val
    }
}

impl Dummy {
    /// Create a new Dummy.
    pub fn new() -> Dummy {
        Dummy {
            outputs: Vec::new(),
        }
    }

    /// Get the output from the fancy computation, consuming the Dummy.
    pub fn get_output(self) -> Vec<u16> {
        self.outputs
    }
}

impl FancyInput for Dummy {
    type Item = DummyVal;
    type Error = DummyError;

    /// Encode a single dummy value.
    fn encode(&mut self, value: u16, modulus: u16) -> Result<DummyVal, DummyError> {
        Ok(DummyVal::new(value, modulus))
    }

    /// Encode a slice of inputs and a slice of moduli as DummyVals.
    fn encode_many(&mut self, xs: &[u16], moduli: &[u16]) -> Result<Vec<DummyVal>, DummyError> {
        if xs.len() != moduli.len() {
            return Err(DummyError::EncodingError);
        }
        Ok(xs
            .iter()
            .zip(moduli.iter())
            .map(|(x, q)| DummyVal::new(*x, *q))
            .collect())
    }

    fn receive_many(&mut self, _moduli: &[u16]) -> Result<Vec<DummyVal>, DummyError> {
        // Receive is undefined for Dummy which is a single party "protocol"
        Err(DummyError::EncodingError)
    }
}

impl Fancy for Dummy {
    type Item = DummyVal;
    type Error = DummyError;

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
    use crate::fancy::{BinaryGadgets, Bundle, BundleGadgets, CrtGadgets};
    use crate::util::{self, crt_inv_factor, RngExt};
    use itertools::Itertools;
    use rand::thread_rng;

    const NITERS: usize = 1 << 10;

    #[test]
    fn test_addition() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let q = rng.gen_usable_composite_modulus();
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut d = Dummy::new();
            {
                let x = d.crt_encode(x, q).unwrap();
                let y = d.crt_encode(y, q).unwrap();
                let z = d.crt_add(&x, &y).unwrap();
                d.output_bundle(&z).unwrap();
            }
            let z = crt_inv_factor(&d.get_output(), q);
            assert_eq!(z, (x + y) % q);
        }
    }

    #[test]
    fn test_subtraction() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let q = rng.gen_usable_composite_modulus();
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut d = Dummy::new();
            {
                let x = d.crt_encode(x, q).unwrap();
                let y = d.crt_encode(y, q).unwrap();
                let z = d.sub_bundles(&x, &y).unwrap();
                d.output_bundle(&z).unwrap();
            }
            let z = crt_inv_factor(&d.get_output(), q);
            assert_eq!(z, (x + q - y) % q);
        }
    }

    #[test]
    fn test_binary_cmul() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let nbits = 64;
            let q = 1 << nbits;
            let x = rng.gen_u128() % q;
            let c = 1 + rng.gen_u128() % q;
            let mut d = Dummy::new();
            {
                let x = d.bin_encode(x, nbits).unwrap();
                let z = d.bin_cmul(&x, c, nbits).unwrap();
                d.output_bundle(&z).unwrap();
            }
            let z = util::u128_from_bits(&d.get_output());
            assert_eq!(z, (x * c) % q);
        }
    }

    #[test]
    fn test_binary_multiplication() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let nbits = 64;
            let q = 1 << nbits;
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut d = Dummy::new();
            {
                let x = d.bin_encode(x, nbits).unwrap();
                let y = d.bin_encode(y, nbits).unwrap();
                let z = d.bin_multiplication_lower_half(&x, &y).unwrap();
                d.output_bundle(&z).unwrap();
            }
            let z = util::u128_from_bits(&d.get_output());
            assert_eq!(z, (x * y) & (q - 1));
        }
    }

    #[test]
    fn max() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);
        let n = 10;
        for _ in 0..NITERS {
            let inps = (0..n).map(|_| rng.gen_u128() % (q / 2)).collect_vec();
            let should_be = *inps.iter().max().unwrap();
            let mut d = Dummy::new();
            {
                let xs = inps
                    .into_iter()
                    .map(|x| d.crt_encode(x, q).unwrap())
                    .collect_vec();
                let z = d.crt_max(&xs, "100%").unwrap();
                d.output_bundle(&z).unwrap();
            }
            let z = crt_inv_factor(&d.get_output(), q);
            assert_eq!(z, should_be);
        }
    }

    #[test]
    fn twos_complement() {
        let mut rng = thread_rng();
        let nbits = 16;
        let q = 1 << nbits;
        for _ in 0..NITERS {
            let x = rng.gen_u128() % q;
            let should_be = (!x + 1) % q;
            let mut d = Dummy::new();
            {
                let x = d.bin_encode(x, nbits).unwrap();
                let y = d.bin_twos_complement(&x).unwrap();
                d.output_bundle(&y).unwrap();
            }
            let outs = d.get_output();
            let y = util::u128_from_bits(&outs);
            assert_eq!(y, should_be, "x={} y={} should_be={}", x, y, should_be);
        }
    }

    #[test]
    fn binary_addition() {
        let mut rng = thread_rng();
        let nbits = 16;
        let q = 1 << nbits;
        for _ in 0..NITERS {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let should_be = (x + y) % q;
            let mut d = Dummy::new();
            {
                let x = d.bin_encode(x, nbits).unwrap();
                let y = d.bin_encode(y, nbits).unwrap();
                let (z, overflow) = d.bin_addition(&x, &y).unwrap();
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

    #[test]
    fn binary_subtraction() {
        let mut rng = thread_rng();
        let nbits = 16;
        let q = 1 << nbits;
        for _ in 0..NITERS {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let should_be = (x - y) % q;
            let mut d = Dummy::new();
            {
                let x = d.bin_encode(x, nbits).unwrap();
                let y = d.bin_encode(y, nbits).unwrap();
                let (z, overflow) = d.bin_subtraction(&x, &y).unwrap();
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

    #[test]
    fn binary_lt() {
        let mut rng = thread_rng();
        let nbits = 16;
        let q = 1 << nbits;
        for _ in 0..NITERS {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let should_be = x < y;
            let mut d = Dummy::new();
            {
                let x = d.bin_encode(x, nbits).unwrap();
                let y = d.bin_encode(y, nbits).unwrap();
                let z = d.bin_lt(&x, &y).unwrap();
                d.output(&z).unwrap();
            }
            let z = d.get_output()[0] > 0;
            assert_eq!(z, should_be, "x={} y={}", x, y);
        }
    }

    #[test]
    fn binary_max() {
        let mut rng = thread_rng();
        let n = 10;
        let nbits = 16;
        let q = 1 << nbits;
        for _ in 0..NITERS {
            let inps = (0..n).map(|_| rng.gen_u128() % q).collect_vec();
            let should_be = *inps.iter().max().unwrap();
            let mut d = Dummy::new();
            {
                let xs = inps
                    .into_iter()
                    .map(|x| d.bin_encode(x, nbits).unwrap())
                    .collect_vec();
                let z = d.bin_max(&xs).unwrap();
                d.output_bundle(&z).unwrap();
            }
            let z = util::u128_from_bits(&d.get_output());
            assert_eq!(z, should_be);
        }
    }

    #[test] // bundle relu
    fn test_relu() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let q = crate::util::modulus_with_nprimes(4 + rng.gen_usize() % 7); // exact relu supports up to 11 primes
            let x = rng.gen_u128() % q;
            let mut d = Dummy::new();
            {
                let x = d.crt_encode(x, q).unwrap();
                let z = d.crt_relu(&x, "100%", None).unwrap();
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

    #[test]
    fn test_mask() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let q = crate::util::modulus_with_nprimes(4 + rng.gen_usize() % 7);
            let x = rng.gen_u128() % q;
            let b = rng.gen_bool();
            let mut d = Dummy::new();
            {
                let b = d.encode(b as u16, 2).unwrap();
                let x = d.crt_encode(x, q).unwrap();
                let z = d.mask(&b, &x).unwrap();
                d.output_bundle(&z).unwrap();
            }
            let z = crt_inv_factor(&d.get_output(), q);
            assert!(if b { z == x } else { z == 0 }, "b={} x={} z={}", b, x, z);
        }
    }

    #[test]
    fn binary_abs() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let nbits = 64;
            let q = 1 << nbits;
            let x = rng.gen_u128() % q;
            let mut d = Dummy::new();
            {
                let x = d.bin_encode(x, nbits).unwrap();
                let z = d.bin_abs(&x).unwrap();
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

    #[test]
    fn binary_demux() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let nbits = 64;
            let q = 1 << nbits;
            let x = rng.gen_u128() % q;
            let mut d = Dummy::new();
            {
                let x = d.bin_encode(x, nbits).unwrap();
                let zs = d.bin_demux(&x).unwrap();
                d.outputs(&zs).unwrap();
            }
            for (i,z) in d.get_output().into_iter().enumerate() {
                if i as u128 == x {
                    assert_eq!(z, 1);
                } else {
                    assert_eq!(z, 0);
                }
            }
        }
    }

    #[test]
    fn binary_eq() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let nbits = rng.gen_usize() % 100 + 2;
            let q = 1 << nbits;
            let x = rng.gen_u128() % q;
            let y = if rng.gen_bool() {
                x
            } else {
                rng.gen_u128() % q
            };
            let mut d = Dummy::new();
            {
                let x = d.bin_encode(x, nbits).unwrap();
                let y = d.bin_encode(y, nbits).unwrap();
                let z = d.eq_bundles(&x, &y).unwrap();
                d.output(&z).unwrap();
            }
            assert_eq!(d.get_output()[0], (x == y) as u16);
        }
    }

    #[test]
    fn test_mixed_radix_addition_msb_only() {
        let mut rng = thread_rng();
        for _ in 0..NITERS {
            let nargs = 2 + rng.gen_usize() % 10;
            let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec();
            let Q: u128 = util::product(&mods);

            println!("nargs={} mods={:?} Q={}", nargs, mods, Q);

            // test maximum overflow
            let xs = (0..nargs)
                .map(|_| {
                    Bundle::new(
                        util::as_mixed_radix(Q - 1, &mods)
                            .into_iter()
                            .zip(&mods)
                            .map(|(x, q)| DummyVal::new(x, *q))
                            .collect_vec(),
                    )
                })
                .collect_vec();

            let mut d = Dummy::new();

            let z = d.mixed_radix_addition_msb_only(&xs).unwrap();
            d.output(&z).unwrap();
            let res = d.get_output()[0];

            let should_be = *util::as_mixed_radix((Q - 1) * (nargs as u128) % Q, &mods)
                .last()
                .unwrap();
            assert_eq!(res, should_be);

            // test random values
            for _ in 0..4 {
                let mut sum = 0;

                let xs = (0..nargs)
                    .map(|_| {
                        let x = rng.gen_u128() % Q;
                        sum = (sum + x) % Q;
                        Bundle::new(
                            util::as_mixed_radix(x, &mods)
                                .into_iter()
                                .zip(&mods)
                                .map(|(x, q)| DummyVal::new(x, *q))
                                .collect_vec(),
                        )
                    })
                    .collect_vec();

                let mut d = Dummy::new();
                let z = d.mixed_radix_addition_msb_only(&xs).unwrap();
                d.output(&z).unwrap();
                let res = d.get_output()[0];

                let should_be = *util::as_mixed_radix(sum, &mods).last().unwrap();
                assert_eq!(res, should_be);
            }
        }
    }

}
