//! Informer runs a fancy computation and learns information from it, like how many of
//! what kind of inputs there are.

use crate::fancy::{Fancy, HasModulus};

/// Implements Fancy. Use to learn information about a fancy computation in a lightweight
/// way.
pub struct Informer {
    garbler_input_moduli: Vec<u16>,
    evaluator_input_moduli: Vec<u16>,
    nconstants: usize,
    noutputs: usize,
    nadds: usize,
    nsubs: usize,
    ncmuls: usize,
    nmuls: usize,
    nprojs: usize,
}

#[derive(Clone, Default, Debug)]
pub struct InformerVal(u16);

impl HasModulus for InformerVal {
    fn modulus(&self) -> u16 { self.0 }
}

impl Informer {
    pub fn new() -> Informer {
        Informer {
            garbler_input_moduli: Vec::new(),
            evaluator_input_moduli: Vec::new(),
            nconstants: 0,
            noutputs: 0,
            nadds: 0,
            nsubs: 0,
            ncmuls: 0,
            nmuls: 0,
            nprojs: 0,
        }
    }

    /// Print information about the fancy computation.
    pub fn print_info(&self) {
        println!("computation info:");
        println!("  garbler inputs:   {}", self.num_garbler_inputs());
        println!("  evaluator inputs: {}", self.num_evaluator_inputs());
        println!("  noutputs:         {}", self.num_outputs());
        println!("  nconsts:          {} // does not reflect constant reuse", self.num_consts());
        println!("  additions:        {}", self.num_adds());
        println!("  subtractions:     {}", self.num_subs());
        println!("  cmuls:            {}", self.num_cmuls());
        println!("  projections:      {}", self.num_projs());
        println!("  multiplications:  {}", self.num_muls());
    }

    /// Number of garbler inputs in the fancy computation.
    pub fn num_garbler_inputs(&self) -> usize {
        self.garbler_input_moduli.len()
    }

    /// Moduli of garbler inputs in the fancy computation.
    pub fn garbler_input_moduli(&self) -> Vec<u16> {
        self.garbler_input_moduli.clone()
    }

    /// Number of evaluator inputs in the fancy computation.
    pub fn num_evaluator_inputs(&self) -> usize {
        self.evaluator_input_moduli.len()
    }

    /// Moduli of evaluator inputs in the fancy computation.
    pub fn evaluator_input_moduli(&self) -> Vec<u16> {
        self.evaluator_input_moduli.clone()
    }

    /// Number of constants in the fancy computation. NOTE: does not reflect that
    /// constants will be reused by most implementors of Fancy.
    pub fn num_consts(&self) -> usize {
        self.nconstants
    }

    /// Number of outputs in the fancy computation.
    pub fn num_outputs(&self) -> usize { self.noutputs }

    /// Number of additions in the fancy computation.
    pub fn num_adds(&self) -> usize { self.nadds }

    /// Number of subtractions in the fancy computation.
    pub fn num_subs(&self) -> usize { self.nsubs }

    /// Number of scalar multiplications in the fancy computation.
    pub fn num_cmuls(&self) -> usize { self.ncmuls }

    /// Number of multiplications in the fancy computation.
    pub fn num_muls(&self) -> usize { self.nmuls }

    /// Number of projections in the fancy computation.
    pub fn num_projs(&self) -> usize { self.nprojs }
}

impl Fancy for Informer {
    type Item = InformerVal;

    fn garbler_input(&mut self, modulus: u16) -> InformerVal {
        self.garbler_input_moduli.push(modulus);
        InformerVal(modulus)
    }

    fn evaluator_input(&mut self, modulus: u16) -> InformerVal {
        self.evaluator_input_moduli.push(modulus);
        InformerVal(modulus)
    }

    fn constant(&mut self, _val: u16, modulus: u16) -> InformerVal {
        self.nconstants += 1;
        InformerVal(modulus)
    }

    fn add(&mut self, x: &InformerVal, y: &InformerVal) -> InformerVal {
        assert!(x.modulus() == y.modulus());
        self.nadds += 1;
        InformerVal(x.modulus())
    }

    fn sub(&mut self, x: &InformerVal, y: &InformerVal) -> InformerVal {
        assert!(x.modulus() == y.modulus());
        self.nsubs += 1;
        InformerVal(x.modulus())
    }

    fn cmul(&mut self, x: &InformerVal, _c: u16) -> InformerVal {
        self.ncmuls += 1;
        InformerVal(x.modulus())
    }

    fn mul(&mut self, x: &InformerVal, y: &InformerVal) -> InformerVal {
        if x.modulus() < y.modulus() {
            return self.mul(y,x);
        }
        self.nmuls += 1;
        InformerVal(x.modulus())
    }

    fn proj(&mut self, x: &InformerVal, modulus: u16, tt: &[u16]) -> InformerVal {
        assert_eq!(tt.len(), x.modulus() as usize);
        assert!(tt.iter().all(|&x| x < modulus));
        self.nprojs += 1;
        InformerVal(modulus)
    }

    fn output(&mut self, _x: &InformerVal) {
        self.noutputs += 1;
    }
}
