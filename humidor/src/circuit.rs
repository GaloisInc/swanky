// This file is part of `humidor`.
// Copyright © 2021 Galois, Inc.
// See LICENSE for licensing information.

//! This module implements arithmetic circuits for the use of Ligero.

use rand::{
    distributions::{Distribution, Uniform},
    Rng,
};
use scuttlebutt::field::FiniteField;

#[cfg(test)]
use crate::util::{arb_test_field, TestField};
#[cfg(test)]
use proptest::{collection::vec as pvec, prelude::*};

/// Operations, where the operation arguments correspond to wire indices, for a
/// Ligero arithmetic circuit over a finite field. Results are always stored in
/// the next available register.
#[derive(Debug, Clone, Copy)]
pub enum Op<Field> {
    /// Add two field elements
    Add(usize, usize),
    /// Multiply two field elements
    Mul(usize, usize),
    /// Subtract one field element from another
    Sub(usize, usize),
    /// Divide one field element by another
    Div(usize, usize),
    /// Load a fixed field element
    LdI(Field),
}

fn rand_ix_pair(rng: &mut impl Rng, min: usize, max: usize) -> (usize, usize) {
    debug_assert!(max - min > 1);

    let s = max - min;

    let a = Uniform::from(0..s).sample(rng);
    let b = Uniform::from(1..s).sample(rng);

    (min + a, min + (a + b) % s)
}

/// Pick an operation at random, for random test circuits.
pub fn random_op<Field>(rng: &mut impl Rng, min_wire: usize, max_wire: usize) -> Op<Field>
where
    Field: FiniteField,
{
    let coin = Uniform::from(0usize..4);
    match coin.sample(rng) {
        0 => {
            let (i, j) = rand_ix_pair(rng, min_wire, max_wire);
            Op::Add(i, j)
        }
        1 => {
            let (i, j) = rand_ix_pair(rng, min_wire, max_wire);
            Op::Mul(i, j)
        }
        2 => {
            let (i, j) = rand_ix_pair(rng, min_wire, max_wire);
            Op::Sub(i, j)
        }
        // Division omitted to avoid accidental division by zero
        3 => Op::LdI(Field::random(rng)),
        _ => panic!("Unreachable"),
    }
}

#[cfg(test)]
fn arb_ix_pair(min: usize, max: usize) -> impl Strategy<Value = (usize, usize)> {
    debug_assert!(max - min > 1);

    let s = max - min;
    (0..s, 1..s).prop_map(move |(a, b)| (min + a, min + (a + b) % s))
}

#[cfg(test)]
pub fn arb_op<Field>(wire_min: usize, wire_max: usize) -> impl Strategy<Value = Op<Field>>
where
    Field: FiniteField + From<u128>,
{
    prop_oneof![
        arb_ix_pair(wire_min, wire_max).prop_map(|(i, j)| Op::Add(i, j)),
        arb_ix_pair(wire_min, wire_max).prop_map(|(i, j)| Op::Mul(i, j)),
        arb_ix_pair(wire_min, wire_max).prop_map(|(i, j)| Op::Sub(i, j)),
        // Division omitted to avoid accidental division by zero
        any::<u64>().prop_map(|f| Op::LdI(Field::from(f as u128))),
    ]
}

impl<Field> Op<Field>
where
    Field: FiniteField,
{
    /// Maximum number of bytes to store an opcode.
    // This should be updated if new ops are added.
    pub const OPCODE_SIZE: usize = 1 +        // opcode type
        if 2*std::mem::size_of::<usize>() > std::mem::size_of::<Field>() {
            2*std::mem::size_of::<usize>()  // Add, Mul, Sub, Div
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
pub struct Ckt<Field> {
    /// The circuit operations.
    pub ops: Vec<Op<Field>>,
    /// Number of field elements for a circuit input.
    pub inp_size: usize,
    /// Subsequence of the input shared with another proof system.
    pub shared: std::ops::Range<usize>, // TODO: Allow non-contiguous shared witness?
}

impl<Field: FiniteField> Ckt<Field> {
    /// Create a new circuit from a circuit size and a sequence of operations.
    pub fn new(inp_size: usize, ops: Vec<Op<Field>>) -> Self {
        Self {
            ops,
            inp_size,
            shared: 0..0,
        }
    }

    /// Create a new circuit, where part of the input is shared with a proof in
    /// a different proof system.
    pub fn new_with_shared(
        inp_size: usize,
        ops: &[Op<Field>],
        shared: std::ops::Range<usize>,
    ) -> Self {
        debug_assert!(shared.end < inp_size);

        Self {
            ops: ops.to_vec(),
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

/// Produce a simple test circuit, as well as an input that should cause it
/// to output zero.
#[cfg(test)]
pub fn test_ckt_zero<Field>() -> (Ckt<Field>, Vec<Field>)
where
    Field: FiniteField + From<u64>,
{
    let ckt = Ckt::new(
        4,
        vec![
            // \w x y z -> x*w + y/w - 5*z
            // reg[0] <- w
            // reg[1] <- x
            // reg[2] <- y
            // reg[3] <- z
            Op::Mul(1, 0),           // reg[4]  <- x * w
            Op::Div(2, 0),           // reg[5]  <- y / w
            Op::Add(4, 5),           // reg[6]  <- (x*w) + (y/w)
            Op::LdI(Field::from(5)), // reg[7]  <- 5
            Op::Mul(7, 3),           // reg[8]  <- 5 * z
            Op::Sub(6, 8),           // reg[9]  <- (x*w+y/w) - (5*z)
        ],
    );

    let (w, x, y) = (Field::from(5u64), Field::from(3u64), Field::from(25u64));
    let z = (x * w + y / w) / Field::from(5); // x*w + y/w - 5*z = 0 ==> z = (x*w + y/w)/5
    let inp = vec![w, x, y, z];

    debug_assert!(ckt.eval(&inp).last().unwrap() == &Field::ZERO);
    (ckt, inp)
}

/// Output a random circuit with an input that evaluates to 0. Both inp_size and
/// ckt_size must be at least 2.
pub fn random_ckt_zero<Field: FiniteField>(
    rng: &mut impl Rng,
    inp_size: usize,
    ckt_size: usize,
) -> (Ckt<Field>, Vec<Field>) {
    debug_assert!(inp_size > 1);
    debug_assert!(ckt_size > 2);

    let mut ops = (0..ckt_size - 2)
        .into_iter()
        .map(|c| random_op(rng, 0, inp_size + c))
        .collect::<Vec<_>>();
    let w = (0..inp_size)
        .into_iter()
        .map(|_| Field::random(rng))
        .collect::<Vec<_>>();

    // XXX: This `clone` might be very expensive!
    let output = Ckt::new(inp_size, ops.clone()).eval(&w);
    ops.push(Op::LdI(*output.last().unwrap()));
    ops.push(Op::Sub(inp_size + ckt_size - 2, inp_size + ckt_size - 3));

    (Ckt::new(inp_size, ops), w)
}

/// Generate an arbitrary circuit with at most the given size.
#[cfg(test)]
#[allow(unused)]
pub fn arb_ckt(inp_size: usize, ckt_size: usize) -> impl Strategy<Value = Ckt<TestField>> {
    debug_assert!(inp_size > 1);
    debug_assert!(ckt_size > 0);

    (1..ckt_size)
        .into_iter()
        .fold(pvec(arb_op(0, inp_size), 1).boxed(), |acc, c| {
            (acc, arb_op(0, inp_size + c))
                .prop_map(|(ops, op)| ops.into_iter().chain(std::iter::once(op)).collect())
                .boxed()
        })
        .prop_map(move |ops| Ckt {
            ops,
            inp_size,
            shared: 0..0,
        })
}

/// Generate an arbitrary circuit with the given size, along with an input that
/// makes it evaluate to zero.
#[cfg(test)]
pub fn arb_ckt_zero(
    inp_size: usize,
    ckt_size: usize,
) -> impl Strategy<Value = (Ckt<TestField>, Vec<TestField>)> {
    debug_assert!(inp_size > 1);
    debug_assert!(ckt_size > 2);

    (
        arb_ckt(inp_size, ckt_size - 2),
        pvec(arb_test_field(), inp_size),
    )
        .prop_map(move |(mut c, w)| {
            let output = c.eval(&w);
            c.ops.push(Op::LdI(*output.last().unwrap()));
            c.ops
                .push(Op::Sub(inp_size + ckt_size - 2, inp_size + ckt_size - 3));

            (c, w)
        })
}

#[test]
fn test_random_ckt_zero() {
    use rand::{rngs::StdRng, SeedableRng};

    let mut rng = StdRng::from_entropy();
    let size = Uniform::from(3..1000);
    for _ in 0..1000 {
        let inp_size = size.sample(&mut rng);
        let ckt_size = size.sample(&mut rng);
        let (c, w): (Ckt<TestField>, Vec<_>) = random_ckt_zero(&mut rng, inp_size, ckt_size);

        assert_eq!(*c.eval(&w).last().unwrap(), TestField::ZERO);
    }
}

#[cfg(test)]
proptest! {
    #[test]
    fn test_arb_ckt_zero(
        (c, w) in (2usize..50, 3usize..50).prop_flat_map(
            |(ws,cs)| arb_ckt_zero(ws,cs))
    ) {
        prop_assert_eq!(*c.eval(&w).last().unwrap(), TestField::ZERO);
    }
}

#[test]
fn test_eval() {
    let (ckt, inp) = test_ckt_zero::<TestField>();

    let w = inp[0];
    let x = inp[1];
    let y = inp[2];
    let z = inp[3];
    let xw = x * w;
    let yw = y / w;
    let xwyw = xw + yw;
    let im5 = TestField::from(5u64);
    let z5 = im5 * z;
    let xwywz5 = xwyw - z5;

    let res = ckt.eval(&vec![w, x, y, z]);
    assert_eq!(res, vec![w, x, y, z, xw, yw, xwyw, im5, z5, xwywz5]);
}
