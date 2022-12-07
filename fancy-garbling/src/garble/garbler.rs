// -*- mode: rust; -*-
//
// This file is part of `fancy-garbling`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::{
    errors::{FancyError, GarblerError},
    fancy::{BinaryBundle, CrtBundle, Fancy, FancyReveal, HasModulus},
    util::{output_tweak, tweak, tweak2, RngExt},
    wire::Wire,
};
use core::hash::BuildHasher;
use rand::{CryptoRng, RngCore};
use scuttlebutt::{AbstractChannel, Block};
use std::collections::HashMap;

/// Streams garbled circuit ciphertexts through a callback.
pub struct Garbler<C, RNG> {
    channel: C,
    deltas: HashMap<u16, Wire>, // map from modulus to associated delta wire-label.
    current_output: usize,
    current_gate: usize,
    rng: RNG,
}

impl<C: AbstractChannel, RNG: CryptoRng + RngCore> Garbler<C, RNG> {
    /// Create a new garbler.
    pub fn new(channel: C, rng: RNG) -> Self {
        Garbler {
            channel,
            deltas: HashMap::new(),
            current_gate: 0,
            current_output: 0,
            rng,
        }
    }

    #[cfg(feature = "serde1")]
    /// Load pre-chosen deltas from a file
    pub fn load_deltas(&mut self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let f = std::fs::File::open(filename)?;
        let reader = std::io::BufReader::new(f);
        let deltas: HashMap<u16, Wire> = serde_json::from_reader(reader)?;
        self.deltas.extend(deltas.into_iter());
        Ok(())
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

    /// Send a wire over the established channel.
    pub fn send_wire(&mut self, wire: &Wire) -> Result<(), GarblerError> {
        self.channel.write_block(&wire.as_block())?;
        Ok(())
    }

    /// Encode a wire, producing the zero wire as well as the encoded value.
    pub fn encode_wire(&mut self, val: u16, modulus: u16) -> (Wire, Wire) {
        let zero = Wire::rand(&mut self.rng, modulus);
        let delta = self.delta(modulus);
        let enc = zero.plus(&delta.cmul(val));
        (zero, enc)
    }

    /// Encode many wires, producing zero wires as well as encoded values.
    pub fn encode_many_wires(
        &mut self,
        vals: &[u16],
        moduli: &[u16],
    ) -> Result<(Vec<Wire>, Vec<Wire>), GarblerError> {
        if vals.len() != moduli.len() {
            return Err(GarblerError::EncodingError);
        }
        assert!(vals.len() == moduli.len());
        let mut gbs = Vec::with_capacity(vals.len());
        let mut evs = Vec::with_capacity(vals.len());
        for (x, q) in vals.iter().zip(moduli.iter()) {
            let (gb, ev) = self.encode_wire(*x, *q);
            gbs.push(gb);
            evs.push(ev);
        }
        Ok((gbs, evs))
    }

    /// Encode a `CrtBundle`, producing zero wires as well as encoded values.
    pub fn crt_encode_wire(
        &mut self,
        val: u128,
        modulus: u128,
    ) -> Result<(CrtBundle<Wire>, CrtBundle<Wire>), GarblerError> {
        let ms = crate::util::factor(modulus);
        let xs = crate::util::crt(val, &ms);
        let (gbs, evs) = self.encode_many_wires(&xs, &ms)?;
        Ok((CrtBundle::new(gbs), CrtBundle::new(evs)))
    }

    /// Encode a `BinaryBundle`, producing zero wires as well as encoded values.
    pub fn bin_encode_wire(
        &mut self,
        val: u128,
        nbits: usize,
    ) -> Result<(BinaryBundle<Wire>, BinaryBundle<Wire>), GarblerError> {
        let xs = crate::util::u128_to_bits(val, nbits);
        let ms = vec![2; nbits];
        let (gbs, evs) = self.encode_many_wires(&xs, &ms)?;
        Ok((BinaryBundle::new(gbs), BinaryBundle::new(evs)))
    }
}

impl<C: AbstractChannel, RNG: RngCore + CryptoRng> FancyReveal for Garbler<C, RNG> {
    fn reveal(&mut self, x: &Wire) -> Result<u16, GarblerError> {
        // The evaluator needs our cooperation in order to see the output.
        // Hence, we call output() ourselves.
        self.output(x)?;
        self.channel.flush()?;
        let val = self.channel.read_u16()?;
        Ok(val)
    }
}

impl<C: AbstractChannel, RNG: RngCore + CryptoRng> Fancy for Garbler<C, RNG> {
    type Item = Wire;
    type Error = GarblerError;

    fn constant(&mut self, x: u16, q: u16) -> Result<Wire, GarblerError> {
        let zero = Wire::rand(&mut self.rng, q);
        let wire = zero.plus(&self.delta(q).cmul_eq(x));
        self.send_wire(&wire)?;
        Ok(zero)
    }

    fn add(&mut self, x: &Wire, y: &Wire) -> Result<Wire, GarblerError> {
        if x.modulus() != y.modulus() {
            return Err(GarblerError::FancyError(FancyError::UnequalModuli));
        }
        Ok(x.plus(y))
    }

    fn sub(&mut self, x: &Wire, y: &Wire) -> Result<Wire, GarblerError> {
        if x.modulus() != y.modulus() {
            return Err(GarblerError::FancyError(FancyError::UnequalModuli));
        }
        Ok(x.minus(y))
    }

    fn cmul(&mut self, x: &Wire, c: u16) -> Result<Wire, GarblerError> {
        Ok(x.cmul(c))
    }

    fn mul(&mut self, A: &Wire, B: &Wire) -> Result<Wire, GarblerError> {
        if A.modulus() < B.modulus() {
            return self.mul(B, A);
        }

        let q = A.modulus();
        let qb = B.modulus();
        let gate_num = self.current_gate();

        let D = self.delta(q);
        let Db = self.delta(qb);

        let r;
        let mut gate = vec![Block::default(); q as usize + qb as usize - 2];

        // hack for unequal moduli
        if q != qb {
            // would need to pack minitable into more than one u128 to support qb > 8
            if qb > 8 {
                return Err(GarblerError::AsymmetricHalfGateModuliMax8(qb));
            }

            r = self.rng.gen_u16() % q;
            let t = tweak2(gate_num as u64, 1);

            let mut minitable = vec![u128::default(); qb as usize];
            let mut B_ = B.clone();
            for b in 0..qb {
                if b > 0 {
                    B_.plus_eq(&Db);
                }
                let new_color = ((r + b) % q) as u128;
                let ct = (u128::from(B_.hash(t)) & 0xFFFF) ^ new_color;
                minitable[B_.color() as usize] = ct;
            }

            let mut packed = 0;
            for i in 0..qb as usize {
                packed += minitable[i] << (16 * i);
            }
            gate.push(Block::from(packed));
        } else {
            r = B.color(); // secret value known only to the garbler (ev knows r+b)
        }

        let g = tweak2(gate_num as u64, 0);

        // X = H(A+aD) + arD such that a + A.color == 0
        let alpha = (q - A.color()) % q; // alpha = -A.color
        let X = A
            .plus(&D.cmul(alpha))
            .hashback(g, q)
            .plus_mov(&D.cmul(alpha * r % q));

        // Y = H(B + bD) + (b + r)A such that b + B.color == 0
        let beta = (qb - B.color()) % qb;
        let Y = B
            .plus(&Db.cmul(beta))
            .hashback(g, q)
            .plus_mov(&A.cmul((beta + r) % q));

        let mut precomp = Vec::with_capacity(q as usize);

        // precompute a lookup table of X.minus(&D_cmul[(a * r % q)])
        //                            = X.plus(&D_cmul[((q - (a * r % q)) % q)])
        let mut X_ = X.clone();
        precomp.push(X_.as_block());
        for _ in 1..q {
            X_.plus_eq(&D);
            precomp.push(X_.as_block());
        }

        let mut A_ = A.clone();
        for a in 0..q {
            if a > 0 {
                A_.plus_eq(&D);
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
        precomp.push(Y_.as_block());
        for _ in 1..q {
            Y_.plus_eq(&A);
            precomp.push(Y_.as_block());
        }

        let mut B_ = B.clone();
        for b in 0..qb {
            if b > 0 {
                B_.plus_eq(&Db);
            }
            // evaluator's half-gate: outputs Y-(b+r)D
            // G = H(B+bD) + Y-(b+r)A
            if B_.color() != 0 {
                gate[q as usize - 1 + B_.color() as usize - 1] =
                    B_.hash(g) ^ precomp[((q - ((b + r) % q)) % q) as usize];
            }
        }

        for block in gate.iter() {
            self.channel.write_block(block)?;
        }
        Ok(X.plus_mov(&Y))
    }

    fn proj(&mut self, A: &Wire, q_out: u16, tt: Option<Vec<u16>>) -> Result<Wire, GarblerError> {
        let tt = tt.ok_or(GarblerError::TruthTableRequired)?;

        let q_in = A.modulus();
        let mut gate = vec![Block::default(); q_in as usize - 1];

        let tao = A.color();
        let g = tweak(self.current_gate());

        let Din = self.delta(q_in);
        let Dout = self.delta(q_out);

        // output zero-wire
        // W_g^0 <- -H(g, W_{a_1}^0 - \tao\Delta_m) - \phi(-\tao)\Delta_n
        let C = A
            .plus(&Din.cmul((q_in - tao) % q_in))
            .hashback(g, q_out)
            .plus_mov(&Dout.cmul((q_out - tt[((q_in - tao) % q_in) as usize]) % q_out));

        // precompute `let C_ = C.plus(&Dout.cmul(tt[x as usize]))`
        let C_precomputed = {
            let mut C_ = C.clone();
            (0..q_out)
                .map(|x| {
                    if x > 0 {
                        C_.plus_eq(&Dout);
                    }
                    C_.as_block()
                })
                .collect::<Vec<Block>>()
        };

        let mut A_ = A.clone();
        for x in 0..q_in {
            if x > 0 {
                A_.plus_eq(&Din); // avoiding expensive cmul for `A_ = A.plus(&Din.cmul(x))`
            }

            let ix = (tao as usize + x as usize) % q_in as usize;
            if ix == 0 {
                continue;
            }

            let ct = A_.hash(g) ^ C_precomputed[tt[x as usize] as usize];
            gate[ix - 1] = ct;
        }

        for block in gate.iter() {
            self.channel.write_block(block)?;
        }
        Ok(C)
    }

    fn output(&mut self, X: &Wire) -> Result<Option<u16>, GarblerError> {
        let q = X.modulus();
        let i = self.current_output();
        let D = self.delta(q);
        for k in 0..q {
            let block = X.plus(&D.cmul(k)).hash(output_tweak(i, k));
            self.channel.write_block(&block)?;
        }
        Ok(None)
    }

    fn output_with_prealloc<H: BuildHasher>(
        &mut self,
        x: &Self::Item,
        _temp_blocks: &mut Vec<Block>,
        _hashes_cache: &mut HashMap<(Self::Item, usize, u16), Block, H>,
    ) -> Result<Option<u16>, Self::Error> {
        // TODO(interstellar)!!! output_with_prealloc vs output
        self.output(x)
    }
}
