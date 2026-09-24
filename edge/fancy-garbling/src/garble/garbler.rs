use crate::{BinaryWireLabel, WireLabel, util::output_tweak};
use fancy_traits::{Fancy, FancyBinary, FancyConstant, FancyEncode, FancyOutput};
use rand::CryptoRng;
#[cfg(feature = "serde")]
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use swanky_channel::Channel;
use swanky_field_binary::F2;
use vectoreyes::U8x16;

/// Streams garbled circuit ciphertexts through a callback.
pub struct Garbler<RNG, Wire> {
    // Zero wirelabel used for binary negation.
    zero: Wire,
    delta_mod_2: Wire,
    // Map from modulus to associated delta wirelabel.
    deltas: HashMap<u16, Wire>,
    current_output: usize,
    current_gate: usize,
    rng: RNG,
}

#[cfg(feature = "serde")]
impl<RNG: CryptoRng, Wire: WireLabel<F2> + DeserializeOwned> Garbler<RNG, Wire> {
    /// Load pre-chosen deltas from a file
    pub fn load_deltas(&mut self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let f = std::fs::File::open(filename)?;
        let reader = std::io::BufReader::new(f);
        let deltas: HashMap<u16, Wire> = serde_json::from_reader(reader)?;
        self.deltas.extend(deltas);
        Ok(())
    }
}

impl<RNG: CryptoRng, Wire: WireLabel<F2>> Garbler<RNG, Wire> {
    /// Create a new [`Garbler`].
    pub fn new(mut rng: RNG) -> Self {
        let delta = Wire::rand_delta(&mut rng, 2);
        // We fix the constant `1` value to `1`, and derive the zero wirelabel
        // as that value XORed with `Δ`.
        let one = Wire::from_repr(U8x16::from(1u128));
        let zero = delta.clone() + one;
        Garbler {
            zero,
            delta_mod_2: delta,
            deltas: HashMap::new(),
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

    /// Create a delta if it has not been created yet for this modulus, otherwise just
    /// return the existing one.
    pub fn delta(&mut self, q: u16) -> Wire {
        if q == 2 {
            self.delta_mod_2.clone()
        } else if let Some(delta) = self.deltas.get(&q) {
            delta.clone()
        } else {
            let w = Wire::rand_delta(&mut self.rng, q);
            self.deltas.insert(q, w.clone());
            w
        }
    }

    /// The current output index of the garbling computation.
    fn current_output(&mut self) -> usize {
        let current = self.current_output;
        self.current_output += 1;
        current
    }

    /// Get the deltas, consuming the [`Garbler`].
    pub fn get_deltas(mut self) -> HashMap<u16, Wire> {
        // Put `delta_mod_2` in the `HashMap` before returning it.
        self.deltas.insert(2, self.delta_mod_2);
        self.deltas
    }

    /// Output a fresh zero wirelabel associated with the provided modulus.
    pub fn encode_zero(&mut self, modulus: u16) -> Wire {
        Wire::rand(&mut self.rng, modulus)
    }
}

impl<RNG: CryptoRng, W: BinaryWireLabel> FancyBinary for Garbler<RNG, W> {
    fn and(
        &mut self,
        A: &Self::Item,
        B: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let delta = self.delta(2);
        let gate_num = self.current_gate();
        let (gate0, gate1, C) = W::garble_and_gate(gate_num, A, B, &delta);
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
            self.zero.clone()
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
            let delta = self.delta(2);
            let zero = self.encode_zero(2);
            let encoded = zero.clone() + delta * (*x).into();
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
        let q = X.modulus();
        let i = self.current_output();
        let D = self.delta(q);
        for k in 0..q {
            let block = (X.clone() + D.clone() * k).hash(output_tweak(i, k));
            channel.write(&block)?;
        }
        Ok(None)
    }
}
