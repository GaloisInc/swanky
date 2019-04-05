//! `Informer` runs a fancy computation and learns information from it.

use crate::error::{FancyError, InformerError};
use crate::fancy::{Fancy, HasModulus};
use std::collections::{HashMap, HashSet};

/// Implements `Fancy`. Used to learn information about a `Fancy` computation in
/// a lightweight way.
pub struct Informer {
    garbler_input_moduli: Vec<u16>,
    evaluator_input_moduli: Vec<u16>,
    constants: HashSet<(u16, u16)>,
    outputs: Vec<u16>,
    nadds: usize,
    nsubs: usize,
    ncmuls: usize,
    nmuls: usize,
    nprojs: usize,
    nciphertexts: usize,
    moduli: HashMap<u16, usize>,
}

/// The item type used by `Informer`. It simply contains the modulus of the
/// wire-label.
#[derive(Clone, Debug)]
pub struct InformerVal(u16);

impl HasModulus for InformerVal {
    fn modulus(&self) -> u16 {
        self.0
    }
}

impl Informer {
    /// Make a new `Informer`.
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
            moduli: HashMap::new(),
        }
    }

    /// Print information about the fancy computation.
    ///
    /// For example, below is the output when run on `circuits/AES-non-expanded.txt`:
    /// ```
    /// computation info:
    ///   garbler inputs:                  128 // comms cost: 16 Kb
    ///   evaluator inputs:                128 // comms cost: 48 Kb
    ///   outputs:                         128
    ///   output ciphertexts:              256 // comms cost: 32 Kb
    ///   constants:                         1 // comms cost: 0.125 Kb
    ///   additions:                     25124
    ///   subtractions:                   1692
    ///   cmuls:                             0
    ///   projections:                       0
    ///   multiplications:                6800
    ///   ciphertexts:                   13600 // comms cost: 1.66 Mb (1700.00 Kb)
    ///   total comms cost:            1.75 Mb // 1700.00 Kb
    /// ```
    pub fn print_info(&self) {
        let mut total = 0.0;
        println!("computation info:");
        let comm = self.num_garbler_inputs() as f64 * 128.0 / 1000.0;
        println!(
            "  garbler inputs:     {:16} // communication: {:.2} Kb",
            self.num_garbler_inputs(),
            comm
        );
        total += comm;
        // The cost of IKNP is 256 bits for one random and one 128 bit string
        // dependent on the random one. This is for each input bit, so for
        // modulus `q` we need to do `log2(q)` OTs.
        let comm = self.evaluator_input_moduli.iter().fold(0.0, |acc, q| {
            acc + (*q as f64).log2().ceil() * 384.0 / 1000.0
        });
        println!(
            "  evaluator inputs:   {:16} // communication: {:.2} Kb",
            self.num_evaluator_inputs(),
            comm
        );
        total += comm;
        let comm = self.num_output_ciphertexts() as f64 * 128.0 / 1000.0;
        println!("  outputs:            {:16}", self.num_outputs());
        println!(
            "  output ciphertexts: {:16} // communication: {:.2} Kb",
            self.num_output_ciphertexts(),
            comm
        );
        total += comm;
        let comm = self.num_consts() as f64 * 128.0 / 1000.0;
        println!(
            "  constants:          {:16} // communication: {:.2} Kb",
            self.num_consts(),
            comm
        );
        total += comm;

        println!("  additions:          {:16}", self.num_adds());
        println!("  subtractions:       {:16}", self.num_subs());
        println!("  cmuls:              {:16}", self.num_cmuls());
        println!("  projections:        {:16}", self.num_projs());
        println!("  multiplications:    {:16}", self.num_muls());
        let cs = self.num_ciphertexts();
        let kb = cs as f64 * 128.0 / 1000.0;
        let mb = kb / 1000.0;
        println!(
            "  ciphertexts:        {:16} // communication: {:.2} Mb ({:.2} Kb)",
            cs, mb, kb
        );
        total += kb;

        let mb = total / 1000.0;
        println!("  total communication:  {:11.2} Mb", mb);
        println!("  wire moduli: {:#?}", self.moduli);
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
    pub fn num_outputs(&self) -> usize {
        self.outputs.len()
    }

    /// Number of output ciphertexts.
    pub fn num_output_ciphertexts(&self) -> usize {
        self.outputs.iter().map(|&m| m as usize).sum()
    }

    /// Number of additions in the fancy computation.
    pub fn num_adds(&self) -> usize {
        self.nadds
    }

    /// Number of subtractions in the fancy computation.
    pub fn num_subs(&self) -> usize {
        self.nsubs
    }

    /// Number of scalar multiplications in the fancy computation.
    pub fn num_cmuls(&self) -> usize {
        self.ncmuls
    }

    /// Number of multiplications in the fancy computation.
    pub fn num_muls(&self) -> usize {
        self.nmuls
    }

    /// Number of projections in the fancy computation.
    pub fn num_projs(&self) -> usize {
        self.nprojs
    }

    /// Number of ciphertexts in the fancy computation.
    pub fn num_ciphertexts(&self) -> usize {
        self.nciphertexts
    }

    fn update_moduli(&mut self, q: u16) {
        let entry = self.moduli.entry(q).or_insert(0);
        *entry += 1;
    }
}

impl Fancy for Informer {
    type Item = InformerVal;
    type Error = InformerError;

    fn garbler_input(&mut self, q: u16, _: Option<u16>) -> Result<InformerVal, InformerError> {
        self.garbler_input_moduli.push(q);
        self.update_moduli(q);
        Ok(InformerVal(q))
    }

    fn evaluator_input(&mut self, q: u16) -> Result<InformerVal, InformerError> {
        self.evaluator_input_moduli.push(q);
        self.update_moduli(q);
        Ok(InformerVal(q))
    }

    fn constant(&mut self, val: u16, q: u16) -> Result<InformerVal, InformerError> {
        self.constants.insert((val, q));
        self.update_moduli(q);
        Ok(InformerVal(q))
    }

    fn add(&mut self, x: &InformerVal, y: &InformerVal) -> Result<InformerVal, InformerError> {
        if x.modulus() != y.modulus() {
            Err(FancyError::UnequalModuli)?;
        }
        self.nadds += 1;
        self.update_moduli(x.modulus());
        Ok(InformerVal(x.modulus()))
    }

    fn sub(&mut self, x: &InformerVal, y: &InformerVal) -> Result<InformerVal, InformerError> {
        if x.modulus() != y.modulus() {
            Err(FancyError::UnequalModuli)?;
        }
        self.nsubs += 1;
        self.update_moduli(x.modulus());
        Ok(InformerVal(x.modulus()))
    }

    fn cmul(&mut self, x: &InformerVal, _: u16) -> Result<InformerVal, InformerError> {
        self.ncmuls += 1;
        self.update_moduli(x.modulus());
        Ok(InformerVal(x.modulus()))
    }

    fn mul(&mut self, x: &InformerVal, y: &InformerVal) -> Result<InformerVal, InformerError> {
        if x.modulus() < y.modulus() {
            return self.mul(y, x);
        }
        self.nmuls += 1;
        self.nciphertexts += x.modulus() as usize + y.modulus() as usize - 2;
        if x.modulus() != y.modulus() {
            // there is an extra ciphertext to support nonequal inputs
            self.nciphertexts += 1;
        }
        self.update_moduli(x.modulus());
        Ok(InformerVal(x.modulus()))
    }

    fn proj(
        &mut self,
        x: &InformerVal,
        q: u16,
        _: Option<Vec<u16>>,
    ) -> Result<InformerVal, InformerError> {
        self.nprojs += 1;
        self.nciphertexts += x.modulus() as usize - 1;
        self.update_moduli(q);
        Ok(InformerVal(q))
    }

    fn output(&mut self, x: &InformerVal) -> Result<(), InformerError> {
        self.outputs.push(x.modulus());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn informer_has_send_and_sync() {
        fn check_send(_: impl Send) {}
        fn check_sync(_: impl Sync) {}
        check_send(Informer::new());
        check_sync(Informer::new());
    }
}
