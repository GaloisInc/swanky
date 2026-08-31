//! AES circuits.

use crate::BinaryCircuit;
use fancy_traits::{Circuit, CircuitInputMapper, CircuitOutputMapper, FancyBinary};
use std::io::Cursor;
use swanky_channel::Channel;
use swanky_error::Result;

/// Circuit for AES-128.
///
/// For an input `(key, block)`, output `AES-128(key, block)`.
pub struct Aes128(BinaryCircuit);

impl Aes128 {
    /// Create a new [`Aes128`] circuit.
    ///
    /// # Performance Note!
    /// This involves parsing a Bristol Format file, and thus is not cheap! Hence,
    /// it is best to reuse this circuit if possible versus calling
    /// [`Aes128::new`] every time this circuit is needed.
    pub fn new() -> Self {
        let circuit = BinaryCircuit::parse_bristol_format(Cursor::<&'static [u8]>::new(
            include_bytes!("../../circuits/bristol-format/AES-non-expanded.txt"),
        ))
        .expect("`AES-non-expanded.txt` file should always parse correctly");
        Self(circuit)
    }
}

impl Default for Aes128 {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FancyBinary> Circuit<F> for Aes128 {
    type Input = ([F::Item; 128], [F::Item; 128]);
    type Output = [F::Item; 128];

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        // Confusingly, the AES Bristol Format file takes the block _first_, and
        // the key _second_. Since the more conventional approach is to take
        // (key, block), we swap the values here before feeding them into the
        // `BinaryCircuit` for evaluation, leaving the interface using the
        // conventional approach.
        let mut combined = inputs.1.to_vec();
        combined.extend_from_slice(&inputs.0);
        let output = self.0.execute(backend, combined, channel)?;
        Ok(output
            .try_into()
            .expect("AES output should always be 128 elements"))
    }
}

impl<F: FancyBinary> CircuitInputMapper<F> for Aes128 {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), 256);
        let (key, block) = inputs.split_at(128);
        (
            key.to_vec().try_into().unwrap(),
            block.to_vec().try_into().unwrap(),
        )
    }

    fn ninputs(&self) -> usize {
        256
    }

    fn modulus(&self, _: usize) -> u16 {
        2
    }
}

impl<F: FancyBinary> CircuitOutputMapper<F> for Aes128 {
    fn flatten(output: Self::Output) -> Vec<F::Item> {
        output.to_vec()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn aes_128() {
        use fancy_plaintext::{Dummy, DummyVal};

        let aes = Aes128::new();

        let key = [DummyVal::new(0, 2); 128];
        let block = [DummyVal::new(0, 2); 128];
        let output = Dummy::eval(&aes, (key, block)).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "01100110111010010100101111010100111011111000101000101100001110111000100001001100111110100101100111001010001101000010101100101110"
        );

        let key = [DummyVal::new(1, 2); 128];
        let block = [DummyVal::new(0, 2); 128];
        let output = Dummy::eval(&aes, (key, block)).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "10100001111101100010010110001100100001110111110101011111110011011000100101100100010010000100010100111000101111111100100100101100"
        );

        let mut key = [DummyVal::new(0, 2); 128];
        for key_part in key.iter_mut().take(8) {
            *key_part = DummyVal::new(1, 2);
        }
        let block = [DummyVal::new(0, 2); 128];
        let output = Dummy::eval(&aes, (key, block)).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "10110001110101110101100000100101011010110010100011111101100001010000101011010100100101000100001000001000110011110001000101010101"
        );

        let mut key = [DummyVal::new(0, 2); 128];
        key[7] = DummyVal::new(1, 2);
        let block = [DummyVal::new(0, 2); 128];
        let output = Dummy::eval(&aes, (key, block)).unwrap();
        assert_eq!(
            output
                .iter()
                .map(|i| i.val().to_string())
                .collect::<String>(),
            "11011100000011101101100001011101111110010110000100011010101110110111001001001001110011011101000101101000110001010100011001111110"
        );
    }

    #[test]
    fn aes_128_gc_eval() {
        use fancy_garbling::{WireMod2, classic::GarbledCircuit};
        use swanky_rng::SwankyRng;

        let aes = Aes128::new();

        let (encoder, gc, _) =
            GarbledCircuit::garble::<WireMod2, _, _>(&aes, SwankyRng::new()).unwrap();
        let inputs = encoder.encode_inputs(&vec![0u16; 256]);
        let key = inputs[..128].try_into().unwrap();
        let block = inputs[128..].try_into().unwrap();
        gc.eval_to_wirelabels(&aes, (key, block)).unwrap();
    }
}
