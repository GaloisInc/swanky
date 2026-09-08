use super::security_warning::warn_proj;
use crate::{
    AllWire, ArithmeticWireLabel, WireMod2,
    garble::binary_and::BinaryWireLabel,
    hash_wires,
    util::{output_tweak, tweak, tweak2},
    wire::WireLabel,
};
use fancy_traits::{
    Fancy, FancyArithmetic, FancyBinary, FancyBinaryConstant, FancyConstant, FancyEncode,
    FancyOutput, FancyProj, HasModulus, is_binary,
};
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

impl<Wire: WireLabel> Evaluator<Wire> {
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

impl<Wire: WireLabel> Default for Evaluator<Wire> {
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

impl FancyBinary for Evaluator<AllWire> {
    /// Overriding `negate` to be a noop: entirely handled on garbler's end
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        is_binary!(x);

        x.clone() + self.one.clone()
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        is_binary!(x);
        is_binary!(y);

        self.add(x, y)
    }

    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        if let (AllWire::Mod2(A), AllWire::Mod2(B)) = (x, y) {
            let gate_num = self.current_gate();
            let gate0 = channel.read()?;
            let gate1 = channel.read()?;
            return Ok(AllWire::Mod2(WireMod2::evaluate_and_gate(
                gate_num, A, B, &gate0, &gate1,
            )));
        }

        // If we got here, one of the wires isn't binary
        is_binary!(x);
        is_binary!(y);

        // Shouldn't be reachable, unless the wire has modulus 2 but is not AllWire::Mod2()
        unreachable!()
    }
}

impl<Wire: WireLabel + ArithmeticWireLabel> FancyArithmetic for Evaluator<Wire> {
    fn add(&mut self, x: &Wire, y: &Wire) -> Wire {
        assert_eq!(x.modulus(), y.modulus());
        x.clone() + y.clone()
    }

    fn sub(&mut self, x: &Wire, y: &Wire) -> Wire {
        assert_eq!(x.modulus(), y.modulus());
        x.clone() - y.clone()
    }

    fn cmul(&mut self, x: &Wire, c: u16) -> Wire {
        x.clone() * c
    }

    fn mul(&mut self, A: &Wire, B: &Wire, channel: &mut Channel) -> swanky_error::Result<Wire> {
        if A.modulus() < B.modulus() {
            return self.mul(B, A, channel);
        }
        let q = A.modulus();
        let qb = B.modulus();
        let unequal = q != qb;
        let ngates = q as usize + qb as usize - 2 + unequal as usize;
        let mut gate = Vec::with_capacity(ngates);
        {
            for _ in 0..ngates {
                let block = channel.read::<U8x16>()?;
                gate.push(block);
            }
        }
        let gate_num = self.current_gate();
        let g = tweak2(gate_num as u64, 0);

        let [hashA, hashB] = hash_wires([A, B], g);

        // garbler's half gate
        let L = if A.color() == 0 {
            Wire::hash_to_mod(hashA, q)
        } else {
            let ct_left = gate[A.color() as usize - 1];
            Wire::from_repr(ct_left ^ hashA, q)
        };

        // evaluator's half gate
        let R = if B.color() == 0 {
            Wire::hash_to_mod(hashB, q)
        } else {
            let ct_right = gate[(q + B.color()) as usize - 2];
            Wire::from_repr(ct_right ^ hashB, q)
        };

        // hack for unequal mods
        // TODO: Batch this with original hash if unequal.
        let new_b_color = if unequal {
            let minitable = *gate.last().unwrap();
            let ct = u128::from(minitable) >> (B.color() * 16);
            let pt = u128::from(B.hash(tweak2(gate_num as u64, 1))) ^ ct;
            pt as u16
        } else {
            B.color()
        };

        let res = L + R + A.clone() * new_b_color;
        Ok(res)
    }
}

impl<Wire: WireLabel + ArithmeticWireLabel> FancyProj for Evaluator<Wire> {
    fn proj(
        &mut self,
        x: &Wire,
        q: u16,
        _: Option<Vec<u16>>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Wire> {
        warn_proj();
        let ngates = (x.modulus() - 1) as usize;
        let mut gate = Vec::with_capacity(ngates);
        for _ in 0..ngates {
            let block = channel.read::<U8x16>()?;
            gate.push(block);
        }
        let t = tweak(self.current_gate());
        if x.color() == 0 {
            Ok(x.hashback(t, q))
        } else {
            let ct = gate[x.color() as usize - 1];
            Ok(Wire::from_repr(ct ^ x.hash(t), q))
        }
    }
}

impl<Wire: WireLabel> Fancy for Evaluator<Wire> {
    type Item = Wire;
}

impl<Wire: WireLabel> FancyConstant for Evaluator<Wire> {
    fn constant(&mut self, _: u16, q: u16, channel: &mut Channel) -> swanky_error::Result<Wire> {
        Ok(Wire::from_repr(channel.read()?, q))
    }
}

impl<Wire: WireLabel> FancyBinaryConstant for Evaluator<Wire> {
    fn constant(&mut self, x: F2) -> Self::Item {
        if x.into() {
            self.one.clone()
        } else {
            // We use the "null" wirelabel to represent zero.
            Default::default()
        }
    }
}

impl<Wire: WireLabel> FancyEncode for Evaluator<Wire> {
    fn encode_many(
        &mut self,
        _values: &[u16],
        _moduli: &[u16],
        _: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        unimplemented!("Evaluator cannot encode values")
    }

    fn receive_many(
        &mut self,
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        moduli
            .iter()
            .map(|q| {
                let block = channel.read()?;
                Ok(Wire::from_repr(block, *q))
            })
            .collect()
    }
}

impl<Wire: WireLabel> FancyOutput for Evaluator<Wire> {
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
