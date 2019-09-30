// -*- mode: rust; -*-
//
// This file is part of `fancy-garbling`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use crate::{
    errors::{EvaluatorError, FancyError},
    fancy::{Fancy, FancyReveal, HasModulus},
    util::{output_tweak, tweak, tweak2},
    wire::Wire,
};
use scuttlebutt::AbstractChannel;

/// Streaming evaluator using a callback to receive ciphertexts as needed.
///
/// Evaluates a garbled circuit on the fly, using messages containing ciphertexts and
/// wires. Parallelizable.
pub struct Evaluator<C> {
    channel: C,
    current_gate: usize,
    current_output: usize,
}

impl<C: AbstractChannel> Evaluator<C> {
    /// Create a new `Evaluator`.
    pub fn new(channel: C) -> Self {
        Evaluator {
            channel,
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

    /// Read a Wire from the reader.
    pub fn read_wire(&mut self, modulus: u16) -> Result<Wire, EvaluatorError> {
        let block = self.channel.read_block()?;
        Ok(Wire::from_block(block, modulus))
    }
}

impl<C: AbstractChannel> FancyReveal for Evaluator<C> {
    fn reveal(&mut self, x: &Wire) -> Result<u16, EvaluatorError> {
        let val = self.output(x)?.expect("Evaluator always outputs Some(u16)");
        self.channel.write_u16(val)?;
        self.channel.flush()?;
        Ok(val)
    }
}

impl<C: AbstractChannel> Fancy for Evaluator<C> {
    type Item = Wire;
    type Error = EvaluatorError;

    fn constant(&mut self, _: u16, q: u16) -> Result<Wire, EvaluatorError> {
        self.read_wire(q)
    }

    fn add(&mut self, x: &Wire, y: &Wire) -> Result<Wire, EvaluatorError> {
        if x.modulus() != y.modulus() {
            return Err(EvaluatorError::FancyError(FancyError::UnequalModuli));
        }
        Ok(x.plus(y))
    }

    fn sub(&mut self, x: &Wire, y: &Wire) -> Result<Wire, EvaluatorError> {
        if x.modulus() != y.modulus() {
            return Err(EvaluatorError::FancyError(FancyError::UnequalModuli));
        }
        Ok(x.minus(y))
    }

    fn cmul(&mut self, x: &Wire, c: u16) -> Result<Wire, EvaluatorError> {
        Ok(x.cmul(c))
    }

    fn mul(&mut self, A: &Wire, B: &Wire) -> Result<Wire, EvaluatorError> {
        if A.modulus() < B.modulus() {
            return self.mul(B, A);
        }
        let q = A.modulus();
        let qb = B.modulus();
        let unequal = q != qb;
        let ngates = q as usize + qb as usize - 2 + unequal as usize;
        let mut gate = Vec::with_capacity(ngates);
        {
            for _ in 0..ngates {
                let block = self.channel.read_block()?;
                gate.push(block);
            }
        }
        let gate_num = self.current_gate();
        let g = tweak2(gate_num as u64, 0);

        // garbler's half gate
        let L = if A.color() == 0 {
            A.hashback(g, q)
        } else {
            let ct_left = gate[A.color() as usize - 1];
            Wire::from_block(ct_left ^ A.hash(g), q)
        };

        // evaluator's half gate
        let R = if B.color() == 0 {
            B.hashback(g, q)
        } else {
            let ct_right = gate[(q + B.color()) as usize - 2];
            Wire::from_block(ct_right ^ B.hash(g), q)
        };

        // hack for unequal mods
        let new_b_color = if unequal {
            let minitable = *gate.last().unwrap();
            let ct = u128::from(minitable) >> (B.color() * 16);
            let pt = u128::from(B.hash(tweak2(gate_num as u64, 1))) ^ ct;
            pt as u16
        } else {
            B.color()
        };

        let res = L.plus_mov(&R.plus_mov(&A.cmul(new_b_color)));
        Ok(res)
    }

    fn proj(&mut self, x: &Wire, q: u16, _: Option<Vec<u16>>) -> Result<Wire, EvaluatorError> {
        let ngates = (x.modulus() - 1) as usize;
        let mut gate = Vec::with_capacity(ngates);
        for _ in 0..ngates {
            let block = self.channel.read_block()?;
            gate.push(block);
        }
        let t = tweak(self.current_gate());
        if x.color() == 0 {
            Ok(x.hashback(t, q))
        } else {
            let ct = gate[x.color() as usize - 1];
            Ok(Wire::from_block(ct ^ x.hash(t), q))
        }
    }

    fn output(&mut self, x: &Wire) -> Result<Option<u16>, EvaluatorError> {
        let q = x.modulus();
        let i = self.current_output();

        // Receive the output ciphertext from the garbler
        let ct = self.channel.read_blocks(q as usize)?;

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
            Err(EvaluatorError::DecodingFailed)
        }
    }
}
