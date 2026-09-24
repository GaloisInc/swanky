use crate::{BinaryWireLabel, WireLabel, util::output_tweak};
use fancy_traits::{Fancy, FancyBinary, FancyConstant, FancyEncode, FancyOutput};
use rand::CryptoRng;
use swanky_channel::Channel;
use swanky_field_binary::F2;
use vectoreyes::U8x16;

/// Streams garbled circuit ciphertexts through a callback.
pub struct Garbler<RNG, Wire> {
    // Zero wirelabel used for binary negation.
    zero: Wire,
    delta: Wire,
    current_output: usize,
    current_gate: usize,
    rng: RNG,
}

impl<RNG: CryptoRng, Wire: WireLabel<F2>> Garbler<RNG, Wire> {
    /// Create a new [`Garbler`].
    pub fn new(mut rng: RNG) -> Self {
        let delta = Wire::rand_delta(&mut rng);
        // We fix the constant `1` value to `1`, and derive the zero wirelabel
        // as that value XORed with `Δ`.
        let one = Wire::from_repr(U8x16::from(1u128));
        let zero = delta + one;
        Garbler {
            zero,
            delta,
            current_gate: 0,
            current_output: 0,
            rng,
        }
    }

    /// The current non-free gate index of the garbling computation
    fn current_gate(&mut self) -> usize {
        let current = self.current_gate;
        self.current_gate += 1;
        current
    }

    /// The `Δ` wirelabel.
    pub fn delta(&mut self) -> Wire {
        self.delta
    }

    /// The current output index of the garbling computation.
    fn current_output(&mut self) -> usize {
        let current = self.current_output;
        self.current_output += 1;
        current
    }

    /// Output a fresh zero wirelabel associated with the provided modulus.
    pub fn encode_zero(&mut self) -> Wire {
        Wire::rand(&mut self.rng)
    }
}

impl<RNG: CryptoRng, W: BinaryWireLabel> FancyBinary for Garbler<RNG, W> {
    fn and(
        &mut self,
        A: &Self::Item,
        B: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let gate_num = self.current_gate();
        let (gate0, gate1, C) = W::garble_and_gate(gate_num, A, B, &self.delta);
        channel.write(&gate0)?;
        channel.write(&gate1)?;
        Ok(C)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        *x + *y
    }

    /// We can negate by having garbler xor wire with Delta
    ///
    /// Since we treat all garbler wires as zero,
    /// xoring with delta conceptually negates the value of the wire
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        self.zero + *x
    }
}

impl<RNG: CryptoRng, Wire: WireLabel<F2>> Fancy for Garbler<RNG, Wire> {
    type Item = Wire;
}

impl<RNG: CryptoRng, Wire: WireLabel<F2>> FancyConstant<F2> for Garbler<RNG, Wire> {
    fn constant(&mut self, x: F2) -> Self::Item {
        if x.into() {
            // `self.zero` corresponds to the zero wirelabel associated with the
            // "one" wirelabel set to `F128b::ONE`.
            self.zero
        } else {
            // Otherwise, the garbler uses the "null" wirelabel to represent zero.
            Default::default()
        }
    }
}

impl<RNG: CryptoRng, Wire: WireLabel<F2>> FancyEncode<F2> for Garbler<RNG, Wire> {
    fn encode_many(
        &mut self,
        values: &[F2],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        let mut zeros = Vec::with_capacity(values.len());
        for x in values.iter() {
            let zero = self.encode_zero();
            let encoded = zero + self.delta * (*x).into();
            channel.write(&encoded.to_repr())?;
            zeros.push(zero);
        }
        Ok(zeros)
    }

    fn receive_many(&mut self, _: usize, _: &mut Channel) -> swanky_error::Result<Vec<Self::Item>> {
        unimplemented!("Garbler cannot receive values")
    }
}

impl<RNG: CryptoRng, Wire: WireLabel<F2>> FancyOutput for Garbler<RNG, Wire> {
    fn output(&mut self, X: &Wire, channel: &mut Channel) -> swanky_error::Result<Option<u16>> {
        let i = self.current_output();
        for k in 0..2 {
            let block = (*X + self.delta() * k).hash(output_tweak(i, k));
            channel.write(&block)?;
        }
        Ok(None)
    }
}
