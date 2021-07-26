// This file is part of `humidor`.
// Copyright © 2021 Galois, Inc.
// See LICENSE for licensing information.

//! This module implements arithmetic circuits for the use of Ligero.

use rand::{Rng, distributions::{Distribution, Uniform}};
use scuttlebutt::field::FiniteField;

#[cfg(test)]
use proptest::{*, prelude::*, collection::vec as pvec};
#[cfg(test)]
use crate::util::{TestField, arb_test_field};

use crate::util::random_field_array;

/// Operations for a Ligero arithmetic circuit over a finite field. Results
/// are always stored in the next available register.
// TODO: Add LDI, SUB, and DIV instructions.
#[derive(Debug, Clone, Copy)]
pub enum Op {
    /// Add two field elements.
    Add(usize, usize),
    /// Multiply two field elements.
    Mul(usize, usize),
}

/// Pick an operation at random, for random test circuits.
pub fn random_op(rng: &mut impl Rng, s: usize) -> Op {
    let index = Uniform::from(0..s);
    let coin = Uniform::from(0usize..2);
    match coin.sample(rng) {
        0 => Op::Add(index.sample(rng), index.sample(rng)),
        1 => Op::Mul(index.sample(rng), index.sample(rng)),
        _ => panic!("Unreachable"),
    }
}

#[cfg(test)]
pub fn arb_op(wire_min: usize, wire_max: usize) -> impl Strategy<Value = Op> {
    let r = wire_min..wire_max;
    prop_oneof![
        (r.clone(),r.clone()).prop_map(|(i,j)| Op::Add(i,j)),
        (r.clone(),r.clone()).prop_map(|(i,j)| Op::Mul(i,j)),
    ]
}

impl Op {
    /// Convert an op to an opcode.
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            Op::Add(i,j) => vec![0].iter()
                .chain(i.to_be_bytes().iter())
                .chain(j.to_be_bytes().iter())
                .cloned()
                .collect(),
            Op::Mul(i,j) => vec![1].iter()
                .chain(i.to_be_bytes().iter())
                .chain(j.to_be_bytes().iter())
                .cloned()
                .collect(),
        }
    }
}

/// An arithmetic circuit for Ligero.
#[derive(Debug, Clone)]
pub struct Ckt<Field> {
    phantom: std::marker::PhantomData<Field>,

    /// The circuit operations.
    pub ops: Vec<Op>,
    /// Number of field elements for a circuit input.
    pub inp_size: usize,
}

impl<Field: FiniteField> Ckt<Field> {
    /// Create a new circuit from a circuit size and a sequence of operations.
    pub fn new(inp_size: usize, ops: &[Op]) -> Self {
        Self {
            phantom: std::marker::PhantomData,
            ops: ops.to_vec(),
            inp_size,
        }
    }

    /// Total size of the extended witness for this circuit (i.e.,
    /// witness size + number of gates).
    pub fn size(&self) -> usize { self.ops.len() + self.inp_size }

    /// Evaluate a circuit on a witness and return an extended witness.
    /// I.e., witness + register outputs.
    pub fn eval(&self, inp: &[Field]) -> Vec<Field> {
        debug_assert_eq!(inp.len(), self.inp_size);

        let mut out: Vec<Field> = Vec::with_capacity(self.size());

        for i in inp {
            out.push(*i);
        }

        for op in &self.ops {
            match *op {
                Op::Add(n, m) => out.push(out[n] + out[m]),
                Op::Mul(n, m) => out.push(out[n] * out[m]),
            }
        }

        out
    }

    #[cfg(test)]
    pub fn test_value() -> Self {
        Self::new(4,
            &vec![ // \w x y z -> w*y + x*z
                Op::Mul(0, 2),
                Op::Mul(1, 3),
                Op::Add(4, 5),
            ],
        )
    }
}

/// Output a random circuit with an input that evaluates to 0. Both inp_size and
/// ckt_size must be at least 2.
pub fn random_ckt_zero<Field: FiniteField>(
    mut rng: impl Rng,
    inp_size: usize,
    ckt_size: usize
) -> (Ckt<Field>, Vec<Field>) {
    debug_assert!(inp_size > 1);
    debug_assert!(ckt_size > 1);

    let mut w: Vec<Field> = random_field_array(&mut rng, inp_size).to_vec();
    let mut ops = vec![];
    let coin = Uniform::from(0usize..2);
    for n in 0 .. ckt_size-1 {
        let index = Uniform::from(1 .. inp_size + n);
        let i = index.sample(&mut rng);
        let j = index.sample(&mut rng);

        ops.push(match coin.sample(&mut rng) {
            0 => Op::Add(i, j),
            1 => Op::Mul(i, j),
            _ => panic!("Unreachable"),
        });
    }

    let output = Ckt::new(inp_size, &ops).eval(&w);
    w[0] = -(*output.last().unwrap());
    ops.push(Op::Add(0, inp_size+ckt_size-2));

    (Ckt::new(inp_size, &ops), w)
}

// XXX: This is a bad way to do this. Creating large circuits will overflow
// the stack. Need to figure out something better, maybe along the lines of
// this: https://altsysrq.github.io/proptest-book/proptest/tutorial/recursive.html
#[cfg(test)]
#[allow(unused)]
pub fn arb_ckt(
    inp_size: usize,
    ckt_size: usize
) -> impl Strategy<Value = Ckt<TestField>> {
    if ckt_size == 0 {
        any::<()>().prop_map(move |()| Ckt::new(inp_size, &vec![])).boxed()
    } else {
        let arb_c = arb_ckt(inp_size, ckt_size - 1);
        let arb_op = arb_op(0, inp_size + ckt_size - 1);
        (arb_c,arb_op).prop_map(|(Ckt::<TestField> {phantom, mut ops, inp_size}, op)| {
            ops.push(op);
            <Ckt<TestField>>::new(inp_size, &ops)
        }).boxed()
    }
}

#[cfg(test)]
#[allow(unused)]
fn arb_ckt_with_inp_hole(
    inp_size: usize,
    ckt_size: usize,
) -> impl Strategy<Value = Ckt<TestField>> {
    if ckt_size == 0 {
        any::<()>().prop_map(move |()| Ckt {
            phantom: std::marker::PhantomData,
            ops: vec![],
            inp_size,
        }).boxed()
    } else {
        let arb_c = arb_ckt_with_inp_hole(inp_size, ckt_size - 1);
        let arb_op = arb_op(1, inp_size + ckt_size - 1);
        (arb_c,arb_op).prop_map(|(Ckt::<TestField> {phantom, mut ops, inp_size}, op)| {
            ops.push(op);
            <Ckt<TestField>>::new(inp_size, &ops)
        }).boxed()
    }
}

// XXX: See comment on arb_ckt, above.
#[cfg(test)]
pub fn arb_ckt_zero(
    inp_size: usize,
    ckt_size: usize,
) -> impl Strategy<Value = (Ckt<TestField>, Vec<TestField>)> {
    (
        arb_ckt_with_inp_hole(inp_size, ckt_size-1),
        pvec(arb_test_field(), inp_size),
    ).prop_map(move |(mut c, mut w)| {
        let output = c.eval(&w);
        w[0] = -(*output.last().unwrap());
        c.ops.push(Op::Add(0, inp_size+ckt_size-2));

        (c, w)
    })
}

#[test]
fn test_random_ckt_zero() {
    use rand::{SeedableRng, rngs::StdRng};

    let mut rng = StdRng::from_entropy();
    let size = Uniform::from(2..1000);
    for _ in 0..1000 {
        let inp_size = size.sample(&mut rng);
        let ckt_size = size.sample(&mut rng);
        let (c, w): (Ckt<TestField>, Vec<_>)
                     = random_ckt_zero(&mut rng, inp_size, ckt_size);

        assert_eq!(*c.eval(&w).last().unwrap(), TestField::ZERO);
    }
}

#[cfg(test)]
proptest! {
    #[test]
    fn test_arb_ckt_zero(
        (c, w) in (2usize..100, 2usize..100).prop_flat_map(
            |(ws,cs)| arb_ckt_zero(ws,cs))
    ) {
        prop_assert_eq!(*c.eval(&w).last().unwrap(), TestField::ZERO);
    }
}

#[test]
fn test_eval() {
    let w    = TestField::from(3u64);
    let x    = TestField::from(5u64);
    let y    = TestField::from(7u64);
    let z    = TestField::from(11u64);
    let wy   = TestField::from(21u64);  // w * y
    let xz   = TestField::from(55u64);  // x * z
    let wyxz = TestField::from(76u64);  // w*y + x*z
    let res  = Ckt::test_value().eval(&vec![w, x, y, z]);
    assert_eq!(res, vec![w, x, y, z, wy, xz, wyxz]);
}
