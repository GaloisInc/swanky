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
