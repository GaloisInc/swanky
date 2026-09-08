use crate::{
    AllWire, ArithmeticWireLabel, BinaryWireLabel, WireLabel, WireMod2,
    util::{output_tweak, tweak, tweak2},
    wire::hash_wires,
};
use fancy_traits::{
    Fancy, FancyArithmetic, FancyBinary, FancyBinaryConstant, FancyConstant, FancyEncode,
    FancyOutput, FancyProj, HasModulus, is_binary,
};
use rand::{CryptoRng, RngExt};
#[cfg(feature = "serde")]
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use swanky_channel::Channel;
use swanky_field_binary::F2;
use vectoreyes::U8x16;

use super::security_warning::warn_proj;

/// Streams garbled circuit ciphertexts through a callback.
pub struct Garbler<RNG, Wire> {
    // Zero wirelabel used for binary negation.
    zero: Wire,
    // Map from modulus to associated delta wirelabel.
    deltas: HashMap<u16, Wire>,
    current_output: usize,
    current_gate: usize,
    rng: RNG,
}

#[cfg(feature = "serde")]
impl<RNG: CryptoRng, Wire: WireLabel + DeserializeOwned> Garbler<RNG, Wire> {
    /// Load pre-chosen deltas from a file
    pub fn load_deltas(&mut self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let f = std::fs::File::open(filename)?;
        let reader = std::io::BufReader::new(f);
        let deltas: HashMap<u16, Wire> = serde_json::from_reader(reader)?;
        self.deltas.extend(deltas);
        Ok(())
    }
}

impl<RNG: CryptoRng, Wire: WireLabel> Garbler<RNG, Wire> {
    /// Create a new [`Garbler`].
    pub fn new(mut rng: RNG) -> Self {
        let delta = Wire::rand_delta(&mut rng, 2);
        // We fix the constant `1` value to `1`, and derive the zero wirelabel
        // as that value XORed with `Δ`.
        let one = Wire::from_repr(U8x16::from(1u128), 2);
        let zero = delta.clone() + one;
        let mut deltas = HashMap::new();
        deltas.insert(2, delta);
        Garbler {
            zero,
            deltas,
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
        if let Some(delta) = self.deltas.get(&q) {
            return delta.clone();
        }
        let w = Wire::rand_delta(&mut self.rng, q);
        self.deltas.insert(q, w.clone());
        w
    }

    /// The current output index of the garbling computation.
    fn current_output(&mut self) -> usize {
        let current = self.current_output;
        self.current_output += 1;
        current
    }

    /// Get the deltas, consuming the Garbler.
    ///
    /// This is useful for reusing wires in multiple garbled circuit instances.
    pub fn get_deltas(self) -> HashMap<u16, Wire> {
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

impl<RNG: CryptoRng> FancyBinary for Garbler<RNG, AllWire> {
    /// We can negate by having garbler xor wire with Delta
    ///
    /// Since we treat all garbler wires as zero,
    /// xoring with delta conceptually negates the value of the wire
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        is_binary!(x);

        let zero = self.zero.clone();
        self.xor(&zero, x)
    }

    /// Xor is just addition
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        is_binary!(x);
        is_binary!(y);

        self.add(x, y)
    }

    /// Use binary and_gate
    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        if let (AllWire::Mod2(A), AllWire::Mod2(B), AllWire::Mod2(ref delta)) =
            (x, y, self.delta(2))
        {
            let gate_num = self.current_gate();
            let (gate0, gate1, C) = WireMod2::garble_and_gate(gate_num, A, B, delta);
            channel.write(&gate0)?;
            channel.write(&gate1)?;
            return Ok(AllWire::Mod2(C));
        }
        // If we got here, one of the wires isn't binary
        is_binary!(x);
        is_binary!(y);

        // Shouldn't be reachable, unless the wire has modulus 2 but is not AllWire::Mod2()
        unreachable!()
    }
}

impl<RNG: CryptoRng, Wire: WireLabel + ArithmeticWireLabel> FancyArithmetic for Garbler<RNG, Wire> {
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
        let gate_num = self.current_gate();

        let D = self.delta(q);
        let Db = self.delta(qb);

        let r;
        let mut gate = vec![Default::default(); q as usize + qb as usize - 2];

        // hack for unequal moduli
        if q != qb {
            // would need to pack minitable into more than one u128 to support qb > 8
            assert!(
                qb <= 8,
                "`B.modulus()` with asymmetric moduli is capped at 8"
            );

            r = self.rng.random::<u16>() % q;
            let t = tweak2(gate_num as u64, 1);

            let mut minitable = vec![u128::default(); qb as usize];
            let mut B_ = B.clone();
            for b in 0..qb {
                if b > 0 {
                    B_ += Db.clone();
                }
                let new_color = ((r + b) % q) as u128;
                let ct = (u128::from(B_.hash(t)) & 0xFFFF) ^ new_color;
                minitable[B_.color() as usize] = ct;
            }

            let mut packed = 0;
            for (i, item) in minitable.iter().enumerate().take(qb as usize) {
                packed += item << (16 * i);
            }
            gate.push(packed.into());
        } else {
            r = B.color(); // secret value known only to the garbler (ev knows r+b)
        }

        let g = tweak2(gate_num as u64, 0);

        // X = H(A+aD) + arD such that a + A.color == 0
        let alpha = (q - A.color()) % q; // alpha = -A.color
        let X1 = A.clone() + D.clone() * alpha;

        // Y = H(B + bD) + (b + r)A such that b + B.color == 0
        let beta = (qb - B.color()) % qb;
        let Y1 = B.clone() + Db.clone() * beta;

        let [hashX, hashY] = hash_wires([&X1, &Y1], g);

        let X = Wire::hash_to_mod(hashX, q) + D.clone() * (alpha * r % q);
        let Y = Wire::hash_to_mod(hashY, q) + A.clone() * ((beta + r) % q);

        let mut precomp = Vec::with_capacity(q as usize);
        // precompute a lookup table of X.minus(&D_cmul[(a * r % q)])
        //                            = X.plus(&D_cmul[((q - (a * r % q)) % q)])
        let mut X_ = X.clone();
        precomp.push(X_.to_repr());
        for _ in 1..q {
            X_ += D.clone();
            precomp.push(X_.to_repr());
        }

        // We can vectorize the hashes here too, but then we need to precompute all `q` sums of A
        // with delta [A, A + D, A + D + D, etc.]
        // Would probably need another alloc which isn't great
        let mut A_ = A.clone();
        for a in 0..q {
            if a > 0 {
                A_ += D.clone();
            }
            // garbler's half-gate: outputs X-arD
            // G = H(A+aD) ^ X+a(-r)D = H(A+aD) ^ X-arD
            if A_.color() != 0 {
                gate[A_.color() as usize - 1] =
                    A_.hash(g) ^ precomp[((q - (a * r % q)) % q) as usize];
            }
        }
        precomp.clear();

        // precompute a lookup table of Y.minus(&A_cmul[((b+r) % q)])
        //                            = Y.plus(&A_cmul[((q - ((b+r) % q)) % q)])
        let mut Y_ = Y.clone();
        precomp.push(Y_.to_repr());
        for _ in 1..q {
            Y_ += A.clone();
            precomp.push(Y_.to_repr());
        }

        // Same note about vectorization as A
        let mut B_ = B.clone();
        for b in 0..qb {
            if b > 0 {
                B_ += Db.clone();
            }
            // evaluator's half-gate: outputs Y-(b+r)D
            // G = H(B+bD) + Y-(b+r)A
            if B_.color() != 0 {
                gate[q as usize - 1 + B_.color() as usize - 1] =
                    B_.hash(g) ^ precomp[((q - ((b + r) % q)) % q) as usize];
            }
        }

        for block in gate.iter() {
            channel.write(block)?;
        }
        Ok(X + Y)
    }
}

impl<RNG: CryptoRng, Wire: WireLabel + ArithmeticWireLabel> FancyProj for Garbler<RNG, Wire> {
    fn proj(
        &mut self,
        A: &Wire,
        q_out: u16,
        tt: Option<Vec<u16>>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Wire> {
        warn_proj();
        assert!(tt.is_some(), "`tt` must not be `None`");
        let tt = tt.unwrap();

        let q_in = A.modulus();
        let mut gate = vec![Default::default(); q_in as usize - 1];

        let tao = A.color();
        let g = tweak(self.current_gate());

        let Din = self.delta(q_in);
        let Dout = self.delta(q_out);

        // output zero-wire
        // W_g^0 <- -H(g, W_{a_1}^0 - \tao\Delta_m) - \phi(-\tao)\Delta_n
        let C = Wire::hash_to_mod(
            (A.clone() + Din.clone() * ((q_in - tao) % q_in)).hash(g),
            q_out,
        ) + Dout.clone() * ((q_out - tt[((q_in - tao) % q_in) as usize]) % q_out);

        // precompute `let C_ = C.plus(&Dout.cmul(tt[x as usize]))`
        let C_precomputed = {
            let mut C_ = C.clone();
            (0..q_out)
                .map(|x| {
                    if x > 0 {
                        C_ += Dout.clone();
                    }
                    C_.to_repr()
                })
                .collect::<Vec<_>>()
        };

        let mut A_ = A.clone();
        for x in 0..q_in {
            if x > 0 {
                A_ += Din.clone(); // avoiding expensive cmul for `A_ = A.plus(&Din.cmul(x))`
            }

            let ix = (tao as usize + x as usize) % q_in as usize;
            if ix == 0 {
                continue;
            }

            let ct = A_.hash(g) ^ C_precomputed[tt[x as usize] as usize];
            gate[ix - 1] = ct;
        }

        for block in gate.iter() {
            channel.write(block)?;
        }
        Ok(C)
    }
}

impl<RNG: CryptoRng, Wire: WireLabel> Fancy for Garbler<RNG, Wire> {
    type Item = Wire;
}

impl<RNG: CryptoRng, Wire: WireLabel> FancyConstant for Garbler<RNG, Wire> {
    fn constant(&mut self, x: u16, q: u16, channel: &mut Channel) -> swanky_error::Result<Wire> {
        let (zero, wire) = Wire::constant(x, q, &self.delta(q), &mut self.rng);
        channel.write(&wire.to_repr())?;
        Ok(zero)
    }
}

impl<RNG: CryptoRng, Wire: WireLabel> FancyBinaryConstant for Garbler<RNG, Wire> {
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

impl<RNG: CryptoRng, Wire: WireLabel> FancyEncode for Garbler<RNG, Wire> {
    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        assert_eq!(values.len(), moduli.len());

        let mut zeros = Vec::with_capacity(values.len());
        for (x, q) in values.iter().zip(moduli.iter()) {
            let delta = self.delta(*q);
            let zero = self.encode_zero(*q);
            let encoded = zero.clone() + delta * *x;
            channel.write(&encoded.to_repr())?;
            zeros.push(zero);
        }
        Ok(zeros)
    }

    fn receive_many(
        &mut self,
        _moduli: &[u16],
        _: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        unimplemented!("Garbler cannot receive values")
    }
}

impl<RNG: CryptoRng, Wire: WireLabel> FancyOutput for Garbler<RNG, Wire> {
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
