//! `Informer` runs a fancy computation and learns information from it.

use crate::{
    fancy::{Fancy, FancyInput, FancyReveal, HasModulus},
    FancyArithmetic, FancyBinary,
};
use std::collections::{HashMap, HashSet};

/// Implements `Fancy`. Used to learn information about a `Fancy` computation in
/// a lightweight way.
pub struct Informer<F: Fancy> {
    /// The underlying fancy object.
    pub underlying: F,
    stats: InformerStats,
}

/// The statistics revealed by the informer.
#[derive(Clone, Debug)]
pub struct InformerStats {
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

impl InformerStats {
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
}

impl std::fmt::Display for InformerStats {
    /// Print information about the fancy computation.
    ///
    /// For example, below is the output when run on `circuits/AES-non-expanded.txt`:
    /// ```text
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
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut total = 0.0;
        writeln!(f, "computation info:")?;
        let comm = self.num_garbler_inputs() as f64 * 128.0 / 1000.0;

        writeln!(
            f,
            "  garbler inputs:     {:16} // communication: {:.2} Kb",
            self.num_garbler_inputs(),
            comm
        )?;
        total += comm;
        // The cost of IKNP is 256 bits for one random and one 128 bit string
        // dependent on the random one. This is for each input bit, so for
        // modulus `q` we need to do `log2(q)` OTs.
        let comm = self.evaluator_input_moduli.iter().fold(0.0, |acc, q| {
            acc + (*q as f64).log2().ceil() * 384.0 / 1000.0
        });

        writeln!(
            f,
            "  evaluator inputs:   {:16} // communication: {:.2} Kb",
            self.num_evaluator_inputs(),
            comm
        )?;
        total += comm;
        let comm = self.num_output_ciphertexts() as f64 * 128.0 / 1000.0;

        writeln!(f, "  outputs:            {:16}", self.num_outputs())?;
        writeln!(
            f,
            "  output ciphertexts: {:16} // communication: {:.2} Kb",
            self.num_output_ciphertexts(),
            comm
        )?;
        total += comm;
        let comm = self.num_consts() as f64 * 128.0 / 1000.0;

        writeln!(
            f,
            "  constants:          {:16} // communication: {:.2} Kb",
            self.num_consts(),
            comm
        )?;
        total += comm;

        writeln!(f, "  additions:          {:16}", self.num_adds())?;
        writeln!(f, "  subtractions:       {:16}", self.num_subs())?;
        writeln!(f, "  cmuls:              {:16}", self.num_cmuls())?;
        writeln!(f, "  projections:        {:16}", self.num_projs())?;
        writeln!(f, "  multiplications:    {:16}", self.num_muls())?;
        let cs = self.num_ciphertexts();
        let kb = cs as f64 * 128.0 / 1000.0;
        let mb = kb / 1000.0;
        writeln!(
            f,
            "  ciphertexts:        {:16} // communication: {:.2} Mb ({:.2} Kb)",
            cs, mb, kb
        )?;
        total += kb;

        let mb = total / 1000.0;
        writeln!(f, "  total communication:  {:11.2} Mb", mb)?;
        writeln!(f, "  wire moduli: {:#?}", self.moduli)?;
        Ok(())
    }
}

impl<F: Fancy> Informer<F> {
    /// Make a new `Informer`.
    pub fn new(underlying: F) -> Informer<F> {
        Informer {
            underlying,
            stats: InformerStats {
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
            },
        }
    }

    /// Get the statistics collected by the `Informer`
    pub fn stats(&self) -> InformerStats {
        self.stats.clone()
    }

    fn update_moduli(&mut self, q: u16) {
        let entry = self.stats.moduli.entry(q).or_insert(0);
        *entry += 1;
    }
}

impl<F: Fancy + FancyInput<Item = <F as Fancy>::Item, Error = <F as Fancy>::Error>> FancyInput
    for Informer<F>
{
    type Item = <F as Fancy>::Item;
    type Error = <F as Fancy>::Error;

    fn receive_many(&mut self, moduli: &[u16]) -> Result<Vec<Self::Item>, Self::Error> {
        self.stats
            .garbler_input_moduli
            .extend(moduli.iter().cloned());
        self.underlying.receive_many(moduli)
    }

    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
    ) -> Result<Vec<Self::Item>, Self::Error> {
        self.stats
            .garbler_input_moduli
            .extend(moduli.iter().cloned());
        self.underlying.encode_many(values, moduli)
    }
}

impl<F: FancyBinary> FancyBinary for Informer<F> {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        let result = self.underlying.xor(x, y)?;
        self.stats.nadds += 1;
        self.update_moduli(x.modulus());
        Ok(result)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        let result = self.underlying.and(x, y)?;
        self.stats.nmuls += 1;
        self.stats.nciphertexts += 2;
        self.update_moduli(x.modulus());
        Ok(result)
    }

    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        let result = self.underlying.negate(x)?;

        // Technically only the garbler adds: noop for the evaluator
        self.stats.nadds += 1;
        self.update_moduli(x.modulus());
        Ok(result)
    }
}

impl<F: FancyArithmetic> FancyArithmetic for Informer<F> {
    // In general, for the below, we first check to see if the result succeeds before
    // updating the stats. That way we can avoid checking multiple times that, e.g.
    // the moduli are equal.

    fn add(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        let result = self.underlying.add(x, y)?;
        self.stats.nadds += 1;
        self.update_moduli(x.modulus());
        Ok(result)
    }

    fn sub(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        let result = self.underlying.sub(x, y)?;
        self.stats.nsubs += 1;
        self.update_moduli(x.modulus());
        Ok(result)
    }

    fn cmul(&mut self, x: &Self::Item, y: u16) -> Result<Self::Item, Self::Error> {
        let result = self.underlying.cmul(x, y)?;
        self.stats.ncmuls += 1;
        self.update_moduli(x.modulus());
        Ok(result)
    }

    fn mul(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        if x.modulus() < y.modulus() {
            return self.mul(y, x);
        }
        let result = self.underlying.mul(x, y)?;
        self.stats.nmuls += 1;
        self.stats.nciphertexts += x.modulus() as usize + y.modulus() as usize - 2;
        if x.modulus() != y.modulus() {
            // there is an extra ciphertext to support nonequal inputs
            self.stats.nciphertexts += 1;
        }
        self.update_moduli(x.modulus());
        Ok(result)
    }

    fn proj(
        &mut self,
        x: &Self::Item,
        q: u16,
        tt: Option<Vec<u16>>,
    ) -> Result<Self::Item, Self::Error> {
        let result = self.underlying.proj(x, q, tt)?;
        self.stats.nprojs += 1;
        self.stats.nciphertexts += x.modulus() as usize - 1;
        self.update_moduli(q);
        Ok(result)
    }
}

impl<F: Fancy> Fancy for Informer<F> {
    type Item = F::Item;
    type Error = F::Error;

    fn constant(&mut self, val: u16, q: u16) -> Result<Self::Item, Self::Error> {
        self.stats.constants.insert((val, q));
        self.update_moduli(q);
        self.underlying.constant(val, q)
    }

    fn output(&mut self, x: &Self::Item) -> Result<Option<u16>, Self::Error> {
        let result = self.underlying.output(x)?;
        self.stats.outputs.push(x.modulus());
        Ok(result)
    }
}

impl<F: Fancy + FancyReveal> FancyReveal for Informer<F> {
    fn reveal(&mut self, x: &Self::Item) -> Result<u16, Self::Error> {
        self.underlying.reveal(x)
    }
}
