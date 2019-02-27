//! Informer runs a fancy computation and learns information from it, like how many of
//! what kind of inputs there are.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::error::{FancyError, InformerError};
use crate::fancy::{Fancy, HasModulus, SyncIndex};

/// Implements Fancy. Use to learn information about a fancy computation in a lightweight
/// way.
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

        println!(
            "  garbler inputs:     {:16} // comms cost: {}kb",
            self.num_garbler_inputs(),
            self.num_garbler_inputs() * 128 / 8 / 1024
        );

        println!(
            "  evaluator inputs:   {:16} // estimated OT cost: {}kb",
            self.num_evaluator_inputs(),
            // cost of IKNP is 256 for 1 random and 1 128 bit string dependent on the random one
            self.num_evaluator_inputs() * 384 * 5 / 8 / 1024 // assuming average moduli have 5 bits
        );

        println!("  outputs:            {:16}", self.num_outputs());
        println!(
            "  output ciphertexts: {:16} // comms cost: {}kb",
            self.num_output_ciphertexts(),
            self.num_output_ciphertexts() * 128 / 8 / 1024
        );

        println!(
            "  constants:          {:16} // comms cost: {}kb",
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
        println!(
            "  ciphertexts:        {:16} // comms cost: {:.2}mb ({:.2}kb)",
            cs, mb, kb
        );

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

    fn garbler_input(
        &self,
        _ix: Option<SyncIndex>,
        modulus: u16,
        _opt_x: Option<u16>,
    ) -> Result<InformerVal, FancyError<InformerError>> {
        self.garbler_input_moduli.lock().unwrap().push(modulus);
        InformerVal(modulus)
    }

    fn evaluator_input(
        &self,
        _ix: Option<SyncIndex>,
        modulus: u16,
    ) -> Result<InformerVal, FancyError<InformerError>> {
        self.evaluator_input_moduli.lock().unwrap().push(modulus);
        InformerVal(modulus)
    }

    fn constant(
        &self,
        _ix: Option<SyncIndex>,
        val: u16,
        modulus: u16,
    ) -> Result<InformerVal, FancyError<InformerError>> {
        self.constants.lock().unwrap().insert((val, modulus));
        InformerVal(modulus)
    }

    fn add(
        &self,
        x: &InformerVal,
        y: &InformerVal,
    ) -> Result<InformerVal, FancyError<InformerError>> {
        if x.modulus() != y.modulus() {
            return Err(FancyError::UnequalModuli {
                name: "add gate",
                xmod: x.modulus(),
                ymod: y.modulus(),
            });
        }
        self.nadds.fetch_add(1, Ordering::SeqCst);
        Ok(InformerVal(x.modulus()))
    }

    fn sub(
        &self,
        x: &InformerVal,
        y: &InformerVal,
    ) -> Result<InformerVal, FancyError<InformerError>> {
        assert!(x.modulus() == y.modulus());
        self.nsubs.fetch_add(1, Ordering::SeqCst);
        InformerVal(x.modulus())
    }

    fn cmul(&self, x: &InformerVal, _c: u16) -> Result<InformerVal, FancyError<InformerError>> {
        self.ncmuls.fetch_add(1, Ordering::SeqCst);
        InformerVal(x.modulus())
    }

    fn mul(
        &self,
        ix: Option<SyncIndex>,
        x: &InformerVal,
        y: &InformerVal,
    ) -> Result<InformerVal, FancyError<InformerError>> {
        if x.modulus() < y.modulus() {
            return self.mul(ix, y, x);
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
        InformerVal(x.modulus())
    }

    fn proj(
        &self,
        _ix: Option<SyncIndex>,
        x: &InformerVal,
        modulus: u16,
        _tt: Option<Vec<u16>>,
    ) -> Result<InformerVal, FancyError<InformerError>> {
        self.nprojs.fetch_add(1, Ordering::SeqCst);
        self.nciphertexts
            .fetch_add(x.modulus() as usize - 1, Ordering::SeqCst);
        InformerVal(modulus)
    }

    fn output(
        &self,
        _ix: Option<SyncIndex>,
        x: &InformerVal,
    ) -> Result<(), FancyError<InformerError>> {
        self.outputs.lock().unwrap().push(x.modulus());
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
