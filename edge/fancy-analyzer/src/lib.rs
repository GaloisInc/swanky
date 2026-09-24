//! [`Fancy`] instantiation for computing gate counts and multiplicative depth
//! of a [`Fancy`] circuit.
#![deny(missing_docs)]

use core::cmp::max;
use fancy_traits::{
    CircuitInputMapper, Fancy, FancyBinary, FancyConstant, FancyEncode, FancyOutput,
};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result};
use swanky_field_binary::F2;

mod wrapper;
pub use wrapper::CircuitAnalyzerWrapper;

/// An instantiation of [`Fancy::Item`] used by [`CircuitAnalyzer`].
#[derive(Clone, Copy, Debug, Default)]
pub struct AnalyzerItem {
    depth: usize,
}

impl AnalyzerItem {
    /// Create a new [`AnalyzerItem`] with the provided modulus.
    pub fn new() -> Self {
        Self { depth: 0 }
    }
}

/// A [`Fancy`] object which counts gates and depth of a
/// [`fancy_traits::Circuit`].
///
/// Specifically, [`CircuitAnalyzer`] stores the number of inputs, ands, xors,
/// negations, constants, multiplications, additions, subtractions, and
/// multiplicative depth of the computation.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct CircuitAnalyzer {
    ninputs: usize,
    nconstants: usize,
    nands: usize,
    nxors: usize,
    nnegs: usize,
    nadds: usize,
    nsubs: usize,
    ncmuls: usize,
    nmuls: usize,
    mul_depth: usize,
}

impl std::fmt::Display for CircuitAnalyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "computation info:")?;
        writeln!(f, "   # inputs:  {:16}", self.ninputs)?;
        writeln!(f, "   # consts:  {:16}", self.nconstants)?;
        writeln!(f, "   # adds:    {:16}", self.nadds)?;
        writeln!(f, "   # subs:    {:16}", self.nsubs)?;
        writeln!(f, "   # cmuls:   {:16}", self.ncmuls)?;
        writeln!(f, "   # muls:    {:16}", self.nmuls)?;
        writeln!(f, "   # ands:    {:16}", self.nands)?;
        writeln!(f, "   # xors:    {:16}", self.nxors)?;
        writeln!(f, "   # negates: {:16}", self.nnegs)?;
        writeln!(
            f,
            "   # arithmetic gates: {}",
            self.nadds + self.nsubs + self.ncmuls + self.nmuls
        )?;
        writeln!(f, "   # boolean gates: {}", self.nands + self.nxors)?;
        writeln!(f, "   mult depth: {}", self.mul_depth)?;
        Ok(())
    }
}

impl CircuitAnalyzer {
    /// Create a new [`CircuitAnalyzer`].
    pub fn new() -> CircuitAnalyzer {
        Default::default()
    }
    /// The number of AND gates in the circuit.
    pub fn nands(&self) -> usize {
        self.nands
    }
    /// The number of input wires of the circuit.
    pub fn ninputs(&self) -> usize {
        self.ninputs
    }
    /// The number of constant wires of the circuit.
    pub fn nconstants(&self) -> usize {
        self.nconstants
    }
    /// The number of XOR gates in the circuit.
    pub fn nxors(&self) -> usize {
        self.nxors
    }

    /// Evaluate a circuit using [`CircuitAnalyzer`].
    ///
    /// The circuit needs to implement [`CircuitInputMapper`] as the circuit
    /// analysis is input-size-dependent.
    pub fn eval<C: CircuitInputMapper<CircuitAnalyzer>>(&mut self, circuit: &C) -> Result<()> {
        Channel::with(std::io::empty(), |channel| {
            let inputs = (0..circuit.ninputs())
                .map(|_| self.receive(channel))
                .collect::<Result<Vec<_>>>()?;
            circuit.execute(self, circuit.map(inputs), channel)?;
            Ok(())
        })
    }
}

impl FancyBinary for CircuitAnalyzer {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        self.nxors += 1;
        AnalyzerItem {
            depth: max(x.depth, y.depth),
        }
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item, _: &mut Channel) -> Result<Self::Item> {
        self.nands += 1;
        let depth = max(x.depth, y.depth) + 1;
        self.mul_depth = max(self.mul_depth, depth);
        Ok(AnalyzerItem { depth })
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        self.nnegs += 1;
        AnalyzerItem { depth: x.depth }
    }
}

impl Fancy for CircuitAnalyzer {
    type Item = AnalyzerItem;
}

impl FancyConstant<F2> for CircuitAnalyzer {
    fn constant(&mut self, _: F2) -> Self::Item {
        self.nconstants += 1;
        AnalyzerItem { depth: 0 }
    }
}

impl FancyEncode<F2> for CircuitAnalyzer {
    fn receive_many(&mut self, n: usize, _: &mut Channel) -> Result<Vec<Self::Item>> {
        self.ninputs += n;
        Ok((0..n).map(|_| AnalyzerItem::new()).collect())
    }

    fn encode_many(&mut self, _: &[F2], _: &mut Channel) -> Result<Vec<Self::Item>> {
        swanky_error::bail!(
            ErrorKind::UnsupportedError,
            "Encoding values is unsupported"
        )
    }
}

impl FancyOutput for CircuitAnalyzer {
    fn output(&mut self, x: &Self::Item, _: &mut Channel) -> Result<Option<u16>> {
        self.mul_depth = max(self.mul_depth, x.depth);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::CircuitAnalyzer;
    use fancy_circuits::crypto::{aes::Aes128, sha::Sha256CompressionFunction};

    #[test]
    fn aes_128_bristol_format_is_correct() {
        let circuit = Aes128::new();
        let mut analyzer = CircuitAnalyzer::new();
        analyzer.eval(&circuit).unwrap();

        // These counts come from <https://nigelsmart.github.io/MPC-Circuits/>
        //
        // Note: If we change the AES circuit, these will need to change!
        assert_eq!(analyzer.nands(), 6400);
        assert_eq!(analyzer.nxors(), 28176);
        assert_eq!(analyzer.nnegs, 2087);
    }

    #[test]
    fn sha256_compression_fn_bristol_fashion_is_correct() {
        let circuit = Sha256CompressionFunction::new();
        let mut analyzer = CircuitAnalyzer::new();
        analyzer.eval(&circuit).unwrap();

        // These counts come from <https://nigelsmart.github.io/MPC-Circuits/>.
        //
        // Note: If we change the SHA-256 compression function circuit, these
        // will need to change!
        assert_eq!(analyzer.nands(), 22573);
        assert_eq!(analyzer.nxors(), 110644);
        assert_eq!(analyzer.nnegs, 1856);
        assert_eq!(analyzer.mul_depth, 1607)
    }
}
