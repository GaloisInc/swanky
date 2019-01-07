//! Dummy implementation of Fancy.
//!
//! Useful for evaluating the circuits produced by Fancy without actually creating any
//! circuits.

use crate::fancy::{Fancy, HasModulus};

/// Simple struct that performs the fancy computation over u16.
pub struct Dummy {
    outputs: Vec<u16>,
    garbler_inputs: Vec<u16>,
    evaluator_inputs: Vec<u16>,
}

/// Wrapper around u16.
#[derive(Clone, Default, Debug)]
pub struct DummyVal {
    val: u16,
    modulus: u16,
}

impl HasModulus for DummyVal {
    fn modulus(&self) -> u16 { self.modulus }
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

    /// Get the output from the fancy computation.
    pub fn get_output(&self) -> Vec<u16> {
        self.outputs.clone()
    }
}

impl Fancy for Dummy {
    type Item = DummyVal;

    fn garbler_input(&mut self, modulus: u16) -> DummyVal {
        assert!(self.garbler_inputs.len() > 0, "not enough garbler inputs");
        let val = self.garbler_inputs.remove(0);
        DummyVal { val, modulus }
    }

    fn evaluator_input(&mut self, modulus: u16) -> DummyVal {
        assert!(self.evaluator_inputs.len() > 0, "not enough evaluator inputs");
        let val = self.evaluator_inputs.remove(0);
        DummyVal { val, modulus }
    }

    fn constant(&mut self, val: u16, modulus: u16) -> DummyVal {
        DummyVal { val, modulus }
    }

    fn add(&mut self, x: &DummyVal, y: &DummyVal) -> DummyVal {
        assert!(x.modulus == y.modulus);
        let val = (x.val + y.val) % x.modulus;
        DummyVal { val, modulus: x.modulus }
    }

    fn sub(&mut self, x: &DummyVal, y: &DummyVal) -> DummyVal {
        assert!(x.modulus == y.modulus);
        let val = (x.modulus + x.val - y.val) % x.modulus;
        DummyVal { val, modulus: x.modulus }
    }

    fn cmul(&mut self, x: &DummyVal, c: u16) -> DummyVal {
        let val = (x.val * c) % x.modulus;
        DummyVal { val, modulus: x.modulus }
    }

    fn mul(&mut self, x: &DummyVal, y: &DummyVal) -> DummyVal {
        if x.modulus < y.modulus {
            return self.mul(y,x);
        }
        let val = (x.val * y.val) % x.modulus;
        DummyVal { val, modulus: x.modulus }
    }

    fn proj(&mut self, x: &DummyVal, modulus: u16, tt: &[u16]) -> DummyVal {
        assert_eq!(tt.len(), x.modulus as usize);
        assert!(tt.iter().all(|&x| x < modulus));
        assert!(x.val < x.modulus);
        let val = tt[x.val as usize];
        DummyVal { val, modulus }
    }

    fn output(&mut self, x: &DummyVal) {
        self.outputs.push(x.val);
    }
}

#[cfg(test)]
mod bundle {
    use super::*;
    use crate::fancy::BundleGadgets;
    use crate::util::{self, RngExt, crt_factor, crt_inv_factor};
    use itertools::Itertools;
    use rand::thread_rng;

    #[test] // bundle addition {{{
    fn addition() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_usable_composite_modulus();
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut d = Dummy::new(&crt_factor(x,q), &crt_factor(y,q));
            {
                let x = d.garbler_input_bundle_crt(q);
                let y = d.evaluator_input_bundle_crt(q);
                let z = d.add_bundles(&x,&y);
                d.output_bundle(&z);
            }
            let z = crt_inv_factor(&d.get_output(),q);
            assert_eq!(z, (x+y)%q);
        }
    }
    //}}}
    #[test] // bundle subtraction {{{
    fn subtraction() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_usable_composite_modulus();
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut d = Dummy::new(&crt_factor(x,q), &crt_factor(y,q));
            {
                let x = d.garbler_input_bundle_crt(q);
                let y = d.evaluator_input_bundle_crt(q);
                let z = d.sub_bundles(&x,&y);
                d.output_bundle(&z);
            }
            let z = crt_inv_factor(&d.get_output(),q);
            assert_eq!(z, (x+q-y)%q);
        }
    }
    //}}}
    #[test] // binary cmul {{{
    fn binary_cmul() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let nbits = 64;
            let q = 1<<nbits;
            let x = rng.gen_u128() % q;
            let c = 1 + rng.gen_u128() % q;
            let mut d = Dummy::new(&util::u128_to_bits(x,nbits), &[]);
            {
                let x = d.garbler_input_bundle(&vec![2;nbits]);
                let z = d.binary_cmul(&x,c,nbits);
                d.output_bundle(&z);
            }
            let z = util::u128_from_bits(&d.get_output());
            assert_eq!(z, (x*c)%q);
        }
    }
    //}}}
    #[test] // bundle max {{{
    fn max() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);
        let n = 10;
        for _ in 0..16 {
            let inps = (0..n).map(|_| rng.gen_u128() % (q/2)).collect_vec();
            let should_be = *inps.iter().max().unwrap();
            let enc_inps = inps.into_iter().flat_map(|x| crt_factor(x,q)).collect_vec();
            let mut d = Dummy::new(&enc_inps, &[]);
            {
                let xs = d.garbler_input_bundles_crt(q,n);
                let z = d.max(&xs);
                d.output_bundle(&z);
            }
            let z = crt_inv_factor(&d.get_output(),q);
            assert_eq!(z, should_be);
        }
    }
    //}}}
    #[test] // binary max {{{
    fn binary_max() {
        let mut rng = thread_rng();
        let n = 10;
        let nbits = 16;
        let q = 1<<nbits;
        for _ in 0..16 {
            let inps = (0..n).map(|_| rng.gen_u128() % q).collect_vec();
            let should_be = *inps.iter().max().unwrap();
            let enc_inps = inps.into_iter().flat_map(|x| util::u128_to_bits(x,nbits)).collect_vec();
            let mut d = Dummy::new(&enc_inps, &[]);
            {
                let xs = d.garbler_input_bundles(&vec![2;nbits], n);
                let z = d.max(&xs);
                d.output_bundle(&z);
            }
            let z = util::u128_from_bits(&d.get_output());
            assert_eq!(z, should_be);
        }
    }
    //}}}
}
