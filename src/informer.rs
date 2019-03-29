//! `Informer` runs a fancy computation and learns information from it.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::error::{FancyError, InformerError};
use crate::fancy::{Fancy, HasModulus};

/// Implements `Fancy`. Used to learn information about a `Fancy` computation in
/// a lightweight way.
pub struct Informer {
    garbler_input_moduli: Arc<Mutex<Vec<u16>>>,
    evaluator_input_moduli: Arc<Mutex<Vec<u16>>>,
    constants: Arc<Mutex<HashSet<(u16, u16)>>>,
    outputs: Arc<Mutex<Vec<u16>>>,
    nadds: Arc<AtomicUsize>,
    nsubs: Arc<AtomicUsize>,
    ncmuls: Arc<AtomicUsize>,
    nmuls: Arc<AtomicUsize>,
    nprojs: Arc<AtomicUsize>,
    nciphertexts: Arc<AtomicUsize>,
    // TODO: we should also accumulate nice info about what are the various
    // moduli in the computation, and how many of such moduli are there. moduli:
    // Arc<Mutex<HashSet<(u16, usize)>>>,
}

#[derive(Clone, Debug)]
pub struct InformerVal(u16);

impl HasModulus for InformerVal {
    fn modulus(&self) -> u16 {
        self.0
    }
}

impl Informer {
    pub fn new() -> Informer {
        Informer {
            garbler_input_moduli: Arc::new(Mutex::new(Vec::new())),
            evaluator_input_moduli: Arc::new(Mutex::new(Vec::new())),
            constants: Arc::new(Mutex::new(HashSet::new())),
            outputs: Arc::new(Mutex::new(Vec::new())),
            nadds: Arc::new(AtomicUsize::new(0)),
            nsubs: Arc::new(AtomicUsize::new(0)),
            ncmuls: Arc::new(AtomicUsize::new(0)),
            nmuls: Arc::new(AtomicUsize::new(0)),
            nprojs: Arc::new(AtomicUsize::new(0)),
            nciphertexts: Arc::new(AtomicUsize::new(0)),
            // moduli: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Print information about the fancy computation.
    ///
    /// For example:
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
        let comm = self.num_garbler_inputs() as f64 * 128.0 / 1024.0;
        println!(
            "  garbler inputs:     {:16} // comms cost: {} Kb",
            self.num_garbler_inputs(),
            comm
        );
        total += comm;
        // The cost of IKNP is 256 bits for one random and one 128 bit string
        // dependent on the random one. This is for each input bit, so for
        // modulus `q` we need to do `log2(q)` OTs.
        let comm = self
            .evaluator_input_moduli
            .lock()
            .unwrap()
            .iter()
            .fold(0.0, |acc, q| {
                acc + (*q as f64).log2().ceil() * 384.0 / 1024.0
            });
        println!(
            "  evaluator inputs:   {:16} // comms cost: {} Kb",
            self.num_evaluator_inputs(),
            comm
        );
        total += comm;
        let comm = self.num_output_ciphertexts() as f64 * 128.0 / 1024.0;
        println!("  outputs:            {:16}", self.num_outputs());
        println!(
            "  output ciphertexts: {:16} // comms cost: {} Kb",
            self.num_output_ciphertexts(),
            comm
        );
        total += comm;
        let comm = self.num_consts() as f64 * 128.0 / 1024.0;
        println!(
            "  constants:          {:16} // comms cost: {} Kb",
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
        let kb = cs as f64 * 128.0 / 1024.0;
        let mb = kb / 1024.0;
        println!(
            "  ciphertexts:        {:16} // comms cost: {:.2} Mb ({:.2} Kb)",
            cs, mb, kb
        );
        total += kb;

        let mb = total / 1024.0;
        println!("  total comms cost:  {:14.2} Mb // {:.2} Kb", mb, kb);
    }

    /// Number of garbler inputs in the fancy computation.
    pub fn num_garbler_inputs(&self) -> usize {
        self.garbler_input_moduli.lock().unwrap().len()
    }

    /// Moduli of garbler inputs in the fancy computation.
    pub fn garbler_input_moduli(&self) -> Vec<u16> {
        self.garbler_input_moduli.lock().unwrap().clone()
    }

    /// Number of evaluator inputs in the fancy computation.
    pub fn num_evaluator_inputs(&self) -> usize {
        self.evaluator_input_moduli.lock().unwrap().len()
    }

    /// Moduli of evaluator inputs in the fancy computation.
    pub fn evaluator_input_moduli(&self) -> Vec<u16> {
        self.evaluator_input_moduli.lock().unwrap().clone()
    }

    /// Number of constants in the fancy computation.
    pub fn num_consts(&self) -> usize {
        self.constants.lock().unwrap().len()
    }

    /// Number of outputs in the fancy computation.
    pub fn num_outputs(&self) -> usize {
        self.outputs.lock().unwrap().len()
    }

    /// Number of output ciphertexts.
    pub fn num_output_ciphertexts(&self) -> usize {
        self.outputs
            .lock()
            .unwrap()
            .iter()
            .map(|&m| m as usize)
            .sum()
    }

    /// Number of additions in the fancy computation.
    pub fn num_adds(&self) -> usize {
        self.nadds.load(Ordering::SeqCst)
    }

    /// Number of subtractions in the fancy computation.
    pub fn num_subs(&self) -> usize {
        self.nsubs.load(Ordering::SeqCst)
    }

    /// Number of scalar multiplications in the fancy computation.
    pub fn num_cmuls(&self) -> usize {
        self.ncmuls.load(Ordering::SeqCst)
    }

    /// Number of multiplications in the fancy computation.
    pub fn num_muls(&self) -> usize {
        self.nmuls.load(Ordering::SeqCst)
    }

    /// Number of projections in the fancy computation.
    pub fn num_projs(&self) -> usize {
        self.nprojs.load(Ordering::SeqCst)
    }

    /// Number of ciphertexts in the fancy computation.
    pub fn num_ciphertexts(&self) -> usize {
        self.nciphertexts.load(Ordering::SeqCst)
    }
}

impl Fancy for Informer {
    type Item = InformerVal;
    type Error = InformerError;

    fn garbler_input(&self, modulus: u16, _: Option<u16>) -> Result<InformerVal, InformerError> {
        self.garbler_input_moduli.lock().unwrap().push(modulus);
        Ok(InformerVal(modulus))
    }

    fn evaluator_input(&self, modulus: u16) -> Result<InformerVal, InformerError> {
        self.evaluator_input_moduli.lock().unwrap().push(modulus);
        Ok(InformerVal(modulus))
    }

    fn constant(&self, val: u16, modulus: u16) -> Result<InformerVal, InformerError> {
        self.constants.lock().unwrap().insert((val, modulus));
        Ok(InformerVal(modulus))
    }

    fn add(&self, x: &InformerVal, y: &InformerVal) -> Result<InformerVal, InformerError> {
        if x.modulus() != y.modulus() {
            Err(FancyError::UnequalModuli)?;
        }
        self.nadds.fetch_add(1, Ordering::SeqCst);
        Ok(InformerVal(x.modulus()))
    }

    fn sub(&self, x: &InformerVal, y: &InformerVal) -> Result<InformerVal, InformerError> {
        if x.modulus() != y.modulus() {
            Err(FancyError::UnequalModuli)?;
        }
        self.nsubs.fetch_add(1, Ordering::SeqCst);
        Ok(InformerVal(x.modulus()))
    }

    fn cmul(&self, x: &InformerVal, _c: u16) -> Result<InformerVal, InformerError> {
        self.ncmuls.fetch_add(1, Ordering::SeqCst);
        Ok(InformerVal(x.modulus()))
    }

    fn mul(&self, x: &InformerVal, y: &InformerVal) -> Result<InformerVal, InformerError> {
        if x.modulus() < y.modulus() {
            return self.mul(y, x);
        }
        self.nmuls.fetch_add(1, Ordering::SeqCst);
        self.nciphertexts.fetch_add(
            x.modulus() as usize + y.modulus() as usize - 2,
            Ordering::SeqCst,
        );
        if x.modulus() != y.modulus() {
            // there is an extra ciphertext to support nonequal inputs
            self.nciphertexts.fetch_add(1, Ordering::SeqCst);
        }
        Ok(InformerVal(x.modulus()))
    }

    fn proj(
        &self,
        x: &InformerVal,
        modulus: u16,
        _: Option<Vec<u16>>,
    ) -> Result<InformerVal, InformerError> {
        self.nprojs.fetch_add(1, Ordering::SeqCst);
        self.nciphertexts
            .fetch_add(x.modulus() as usize - 1, Ordering::SeqCst);
        Ok(InformerVal(modulus))
    }

    fn output(&self, x: &InformerVal) -> Result<(), InformerError> {
        self.outputs.lock().unwrap().push(x.modulus());
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
