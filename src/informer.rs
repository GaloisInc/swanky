//! Informer runs a fancy computation and learns information from it, like how many of
//! what kind of inputs there are.

use crate::fancy::{Fancy, HasModulus};
use std::collections::HashSet;

/// Implements Fancy. Use to learn information about a fancy computation in a lightweight
/// way.
pub struct Informer {
    garbler_input_moduli: Vec<u16>,
    evaluator_input_moduli: Vec<u16>,
    constants: HashSet<(u16,u16)>,
    outputs: Vec<u16>,
    nadds: usize,
    nsubs: usize,
    ncmuls: usize,
    nmuls: usize,
    nprojs: usize,
    nciphertexts: usize,
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
            constants: HashSet::new(),
            outputs: Vec::new(),
            nadds: 0,
            nsubs: 0,
            ncmuls: 0,
            nmuls: 0,
            nprojs: 0,
            nciphertexts: 0,
        }
    }

    /// Print information about the fancy computation.
    ///
    /// For example:
    /// ```
    /// computation info:
    ///   garbler inputs:             345600 // comms cost: 5400kb
    ///   evaluator inputs:           345600 // OT cost: 10800kb
    ///   outputs:                         1 // comms cost: ??kb
    ///   constants:                       2 // comms cost: 0kb
    ///   additions:                 9169197
    ///   subtractions:                    0
    ///   cmuls:                           0
    ///   projections:                     0
    ///   multiplications:           2073599
    ///   ciphertexts:               4147198 // comms cost: 63.28mb (64799.97kb)
    ///   total comms cost:          79.10mb // 81000.00kb
    /// ```
    pub fn print_info(&self) {
        println!("computation info:");

        println!("  garbler inputs:     {:16} // comms cost: {}kb",
            self.num_garbler_inputs(),
            self.num_garbler_inputs() * 128 / 8 / 1024
        );

        println!("  evaluator inputs:   {:16} // OT cost: {}kb",
            self.num_evaluator_inputs(),
            // cost of IKNP is 256 for 1 random and 1 128 bit string dependent on the random one
            self.num_evaluator_inputs() * 256 / 8 / 1024
        );

        println!("  outputs:            {:16}", self.num_outputs());
        println!("  output ciphertexts: {:16} // comms cost: {}kb",
            self.num_output_ciphertexts(),
            self.num_output_ciphertexts() * 128 / 8 / 1024
        );

        println!("  constants:          {:16} // comms cost: {}kb",
            self.num_consts(),
            self.num_consts() * 128 / 8 / 1024
        );

        println!("  additions:          {:16}", self.num_adds());
        println!("  subtractions:       {:16}", self.num_subs());
        println!("  cmuls:              {:16}", self.num_cmuls());
        println!("  projections:        {:16}", self.num_projs());
        println!("  multiplications:    {:16}", self.num_muls());
        let cs = self.num_ciphertexts();
        let kb = cs as f64 * 128.0 / 8.0 / 1024.0;
        let mb = kb / 1024.0;
        println!("  ciphertexts:        {:16} // comms cost: {:.2}mb ({:.2}kb)", cs, mb, kb);

        // compute total comms cost
        let mut comms_bits = 0;
        comms_bits += self.num_garbler_inputs() * 128;
        comms_bits += self.num_evaluator_inputs() * 256;
        comms_bits += self.num_consts() * 128;
        comms_bits += self.num_ciphertexts() * 128;
        comms_bits += self.num_output_ciphertexts() * 128;
        let kb = comms_bits as f64 / 8.0 / 1024.0;
        let mb = kb / 1024.0;
        println!("  total comms cost:   {:14.2}mb // {:.2}kb", mb, kb);
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

    /// Number of constants in the fancy computation.
    pub fn num_consts(&self) -> usize {
        self.constants.len()
    }

    /// Number of outputs in the fancy computation.
    pub fn num_outputs(&self) -> usize { self.outputs.len() }

    /// Number of output ciphertexts.
    pub fn num_output_ciphertexts(&self) -> usize {
        self.outputs.iter().map(|&m| m as usize).sum()
    }

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

    /// Number of ciphertexts in the fancy computation.
    pub fn num_ciphertexts(&self) -> usize { self.nciphertexts }
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

    fn constant(&mut self, val: u16, modulus: u16) -> InformerVal {
        match self.constants.get(&(val,modulus)) {
            None => {
                self.constants.insert((val,modulus));
            }
            _ => (),
        }
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
        self.nciphertexts += x.modulus() as usize + y.modulus() as usize - 2;
        if x.modulus() != y.modulus() {
            // there is an extra ciphertext to support nonequal inputs
            self.nciphertexts += 1;
        }
        InformerVal(x.modulus())
    }

    fn proj(&mut self, x: &InformerVal, modulus: u16, tt: &[u16]) -> InformerVal {
        assert_eq!(tt.len(), x.modulus() as usize);
        assert!(tt.iter().all(|&x| x < modulus));
        self.nprojs += 1;
        self.nciphertexts += x.modulus() as usize - 1;
        InformerVal(modulus)
    }

    fn output(&mut self, x: &InformerVal) {
        self.outputs.push(x.modulus());
    }
}
