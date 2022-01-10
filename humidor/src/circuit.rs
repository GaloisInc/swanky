// This file is part of `humidor`.
// Copyright © 2021 Galois, Inc.
// See LICENSE for licensing information.

//! This module implements arithmetic circuits for the use of Ligero.

use scuttlebutt::field::FiniteField;

/// Type denoting a wire index.
pub type Index = usize;

/// Operations, where the operation arguments correspond to wire indices, for a
/// Ligero arithmetic circuit over a finite field. Results are always stored in
/// the next available register.
#[derive(Debug, Clone, Copy)]
pub enum Op<Field> {
    /// Add two field elements
    Add(Index, Index),
    /// Multiply two field elements
    Mul(Index, Index),
    /// Subtract one field element from another
    Sub(Index, Index),
    /// Divide one field element by another
    Div(Index, Index),
    /// Load a fixed field element
    LdI(Field),
}

impl<Field: FiniteField> Op<Field> {
    /// Maximum number of bytes to store an opcode.
    // This should be updated if new ops are added.
    pub const OPCODE_SIZE: usize = 1 +        // opcode type
        if 2*std::mem::size_of::<Index>() > std::mem::size_of::<Field>() {
            2*std::mem::size_of::<Index>()  // Add, Mul, Sub, Div
        } else {
            std::mem::size_of::<Field>()    // LdI
        };

    /// Convert an op to an opcode.
    pub fn append_bytes(&self, bs: &mut Vec<u8>) {
        match self {
            Op::Add(i, j) => {
                bs.push(0u8);
                i.to_le_bytes().iter().for_each(|&b| bs.push(b));
                j.to_le_bytes().iter().for_each(|&b| bs.push(b));
            }
            Op::Mul(i, j) => {
                bs.push(1u8);
                i.to_le_bytes().iter().for_each(|&b| bs.push(b));
                j.to_le_bytes().iter().for_each(|&b| bs.push(b));
            }
            Op::Sub(i, j) => {
                bs.push(2u8);
                i.to_le_bytes().iter().for_each(|&b| bs.push(b));
                j.to_le_bytes().iter().for_each(|&b| bs.push(b));
            }
            Op::Div(i, j) => {
                bs.push(3u8);
                i.to_le_bytes().iter().for_each(|&b| bs.push(b));
                j.to_le_bytes().iter().for_each(|&b| bs.push(b));
            }
            Op::LdI(f) => {
                bs.push(4u8);
                f.to_bytes().iter().for_each(|&b| bs.push(b));
            }
        }
    }
}

/// An arithmetic circuit for Ligero.
#[derive(Debug, Clone)]
pub struct Circuit<Field> {
    /// The circuit operations.
    pub ops: Vec<Op<Field>>,
    /// Number of field elements for a circuit input.
    pub inp_size: usize,
    /// Subsequence of the input shared with another proof system.
    pub shared: std::ops::Range<usize>, // TODO: Allow non-contiguous shared witness?
}

impl<Field: FiniteField> Circuit<Field> {
    /// Create a new circuit from a circuit size and a sequence of operations.
    pub fn new(
        inp_size: usize,
        ops: Vec<Op<Field>>,
        shared: Option<std::ops::Range<usize>>,
    ) -> Self {
        let shared = shared.unwrap_or(0..0);
        debug_assert!(shared.end < inp_size);
        Self {
            ops,
            inp_size,
            shared,
        }
    }

    /// Total size of the extended witness for this circuit (i.e.,
    /// witness size + number of gates).
    pub fn size(&self) -> usize {
        self.ops.len() + self.inp_size
    }

    /// Evaluate a circuit on a witness and return an extended witness.
    /// I.e., witness + register outputs.
    pub fn eval(&self, inp: &[Field]) -> Vec<Field> {
        debug_assert_eq!(inp.len(), self.inp_size);

        let mut out: Vec<Field> = Vec::with_capacity(self.size());

        for i in inp {
            out.push(*i);
        }

        for op in &self.ops {
            debug_assert!(if let Op::Add(n, m) = *op {
                n != m
            } else {
                true
            });
            debug_assert!(if let Op::Mul(n, m) = *op {
                n != m
            } else {
                true
            });
            debug_assert!(if let Op::Sub(n, m) = *op {
                n != m
            } else {
                true
            });
            debug_assert!(if let Op::Div(n, m) = *op {
                n != m
            } else {
                true
            });
            match *op {
                Op::Add(n, m) => out.push(out[n] + out[m]),
                Op::Mul(n, m) => out.push(out[n] * out[m]),
                Op::Sub(n, m) => out.push(out[n] - out[m]),
                Op::Div(n, m) => out.push(out[n] / out[m]),
                Op::LdI(f) => out.push(f),
            }
        }
        out
    }
}
