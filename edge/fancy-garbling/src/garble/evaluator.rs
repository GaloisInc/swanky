use crate::{BinaryWireLabel, util::output_tweak, wire::WireLabel};
use fancy_traits::{Fancy, FancyBinary, FancyConstant, FancyEncode, FancyOutput};
use swanky_channel::Channel;
use swanky_error::ErrorKind;
use swanky_field_binary::F2;
use vectoreyes::U8x16;

/// Streaming evaluator using a callback to receive ciphertexts as needed.
///
/// Evaluates a garbled circuit on the fly, using messages containing ciphertexts and
/// wires. Parallelizable.
pub struct Evaluator<Wire> {
    one: Wire,
    current_gate: usize,
    current_output: usize,
}

impl<Wire: WireLabel<F2>> Evaluator<Wire> {
    /// Create a new [`Evaluator`].
    pub fn new() -> Self {
        // We set the constant `1` wirelabel to simply be `1`.
        let one = Wire::from_repr(U8x16::from(1u128), 2);
        Evaluator {
            one,
            current_gate: 0,
            current_output: 0,
        }
    }

    /// The current non-free gate index of the garbling computation.
    fn current_gate(&mut self) -> usize {
        let current = self.current_gate;
        self.current_gate += 1;
        current
    }

    /// The current output index of the garbling computation.
    fn current_output(&mut self) -> usize {
        let current = self.current_output;
        self.current_output += 1;
        current
    }
}

impl<Wire: WireLabel<F2>> Default for Evaluator<Wire> {
    fn default() -> Self {
        Self::new()
    }
}

impl<W: BinaryWireLabel> FancyBinary for Evaluator<W> {
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        *x + self.one
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        *x + *y
    }

    fn and(
        &mut self,
        A: &Self::Item,
        B: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let gate_num = self.current_gate();
        let gate0 = channel.read()?;
        let gate1 = channel.read()?;
        Ok(W::evaluate_and_gate(gate_num, A, B, &gate0, &gate1))
    }
}

impl<Wire: WireLabel<F2>> Fancy for Evaluator<Wire> {
    type Item = Wire;
}

impl<Wire: WireLabel<F2>> FancyConstant<F2> for Evaluator<Wire> {
    fn constant(&mut self, x: F2) -> Self::Item {
        if x.into() {
            self.one.clone()
        } else {
            // We use the "null" wirelabel to represent zero.
            Default::default()
        }
    }
}

impl<Wire: WireLabel<F2>> FancyEncode<F2> for Evaluator<Wire> {
    fn encode_many(&mut self, _: &[F2], _: &mut Channel) -> swanky_error::Result<Vec<Self::Item>> {
        unimplemented!("Evaluator cannot encode values")
    }

    fn receive_many(
        &mut self,
        n: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        (0..n)
            .map(|_| {
                let block = channel.read()?;
                Ok(Wire::from_repr(block, 2))
            })
            .collect()
    }
}

impl<Wire: WireLabel<F2>> FancyOutput for Evaluator<Wire> {
    fn output(&mut self, x: &Wire, channel: &mut Channel) -> swanky_error::Result<Option<u16>> {
        let q = x.modulus();
        let i = self.current_output();

        // Receive the output ciphertext from the garbler
        let mut ct = Vec::with_capacity(q as usize);
        for _ in 0..q {
            let block = channel.read()?;
            ct.push(block);
        }

        // Attempt to brute force x using the output ciphertext
        let mut decoded = None;
        for k in 0..q {
            let hashed_wire = x.hash(output_tweak(i, k));
            if hashed_wire == ct[k as usize] {
                decoded = Some(k);
                break;
            }
        }

        if let Some(output) = decoded {
            Ok(Some(output))
        } else {
            swanky_error::bail!(ErrorKind::OtherError, "Decoding failed");
        }
    }
}
