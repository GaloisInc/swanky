use crate::{AnalyzerItem, CircuitAnalyzer};
use core::fmt::Debug;
use fancy_traits::{Fancy, FancyBinary, HasModulus};
use std::ops::Deref;
use swanky_channel::Channel;
use swanky_error::Result;

/// The [`Fancy::Item`] type for [`CircuitAnalyzerWrapper`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Wire<W>(W, AnalyzerItem);

impl<W: HasModulus> Wire<W> {
    pub fn new(value: W) -> Self {
        let modulus = value.modulus();
        Self(value, AnalyzerItem::new(modulus))
    }
}

impl<W> Deref for Wire<W> {
    type Target = W;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<W: HasModulus> HasModulus for Wire<W> {
    fn modulus(&self) -> u16 {
        self.0.modulus()
    }
}

/// A [`Fancy`] object for running a computation alongside [`CircuitAnalyzer`].
pub struct CircuitAnalyzerWrapper<F> {
    internal: F,
    analyzer: CircuitAnalyzer,
}

impl<F> CircuitAnalyzerWrapper<F> {
    /// Create a new [`CircuitAnalyzerWrapper`] for some internal object.
    pub fn new(internal: F) -> Self {
        Self {
            internal,
            analyzer: CircuitAnalyzer::new(),
        }
    }

    /// Extract the internal object, consuming `self`.
    pub fn internal(self) -> F {
        self.internal
    }
}

impl<F> Deref for CircuitAnalyzerWrapper<F> {
    type Target = CircuitAnalyzer;

    fn deref(&self) -> &Self::Target {
        &self.analyzer
    }
}

impl<F: Fancy> Fancy for CircuitAnalyzerWrapper<F> {
    type Item = Wire<F::Item>;

    fn constant(&mut self, x: u16, q: u16, channel: &mut Channel) -> Result<Self::Item> {
        Ok(Wire(
            self.internal.constant(x, q, channel)?,
            self.analyzer.constant(x, q, channel)?,
        ))
    }
}

impl<F: FancyBinary> FancyBinary for CircuitAnalyzerWrapper<F> {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        Wire(self.internal.xor(&x.0, &y.0), self.analyzer.xor(&x.1, &y.1))
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item, channel: &mut Channel) -> Result<Self::Item> {
        Ok(Wire(
            self.internal.and(&x.0, &y.0, channel)?,
            self.analyzer.and(&x.1, &y.1, channel)?,
        ))
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        Wire(self.internal.negate(&x.0), self.analyzer.negate(&x.1))
    }
}

#[cfg(test)]
mod tests {
    use fancy_circuits::crypto::aes::Aes128;
    use fancy_plaintext::{Dummy, DummyVal};
    use fancy_traits::Circuit;
    use swanky_channel::Channel;

    use crate::{CircuitAnalyzerWrapper, wrapper::Wire};

    #[test]
    fn aes_128_bristol_format_is_correct() {
        let circuit = Aes128::new();
        let mut analyzer = CircuitAnalyzerWrapper::new(Dummy::new());
        let key = [Wire::new(DummyVal::new_bool(false)); 128];
        let block = [Wire::new(DummyVal::new_bool(false)); 128];

        let output = Channel::with(std::io::empty(), |channel| {
            circuit.execute(&mut analyzer, (key, block), channel)
        })
        .unwrap();

        // Check that the plaintext computation was done correctly.
        assert_eq!(
            output
                .iter()
                .map(|out| out.val().to_string())
                .collect::<String>(),
            "01100110111010010100101111010100111011111000101000101100001110111000100001001100111110100101100111001010001101000010101100101110"
        );

        // These counts come from
        // <https://nigelsmart.github.io/MPC-Circuits/old-circuits.html>
        //
        // Note: If we change the AES circuit, these will need to change!
        assert_eq!(analyzer.nands(), 6800);
        assert_eq!(analyzer.nxors(), 25124);
        assert_eq!(analyzer.nnegs, 1692);
    }
}
