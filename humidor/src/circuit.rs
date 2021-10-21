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
#[derive(Debug, Clone, Copy)]
pub enum Op<Field> {
    /// Add two field elements.
    Add(usize, usize),
    /// Multiply two field elements.
    Mul(usize, usize),
    /// Subtract one field element from another
    Sub(usize, usize),
    /// Divide one field element by another
    Div(usize, usize),
    /// Load a fixed field element
    LdI(Field),
}

/// Pick an operation at random, for random test circuits.
pub fn random_op<Field>(rng: &mut impl Rng, s: usize) -> Op<Field>
    where Field: FiniteField
{
    let index = Uniform::from(0..s);
    let coin = Uniform::from(0usize..4);
    match coin.sample(rng) {
        0 => Op::Add(index.sample(rng), index.sample(rng)),
        1 => Op::Mul(index.sample(rng), index.sample(rng)),
        2 => Op::Sub(index.sample(rng), index.sample(rng)),
        // Division omitted to avoid accidental division by zero
        3 => Op::LdI(Field::random(rng)),
        _ => panic!("Unreachable"),
    }
}

#[cfg(test)]
pub fn arb_op<Field>(wire_min: usize, wire_max: usize)
    -> impl Strategy<Value = Op<Field>>
    where Field: FiniteField + From<u128>
{
    let r = wire_min..wire_max;
    prop_oneof![
        (r.clone(),r.clone()).prop_map(|(i,j)| Op::Add(i,j)),
        (r.clone(),r.clone()).prop_map(|(i,j)| Op::Mul(i,j)),
        (r.clone(),r.clone()).prop_map(|(i,j)| Op::Sub(i,j)),
        // Division omitted to avoid accidental division by zero
        (0..Field::MODULUS).prop_map(|f| Op::LdI(Field::from(f))),
    ]
}

impl<Field> Op<Field>
    where Field: FiniteField
{
    /// Convert an op to an opcode.
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            Op::Add(i,j) => vec![0].iter()
                .chain(i.to_le_bytes().iter())
                .chain(j.to_le_bytes().iter())
                .cloned()
                .collect(),
            Op::Mul(i,j) => vec![1].iter()
                .chain(i.to_le_bytes().iter())
                .chain(j.to_le_bytes().iter())
                .cloned()
                .collect(),
            Op::Sub(i,j) => vec![2].iter()
                .chain(i.to_le_bytes().iter())
                .chain(j.to_le_bytes().iter())
                .cloned()
                .collect(),
            Op::Div(i,j) => vec![3].iter()
                .chain(i.to_le_bytes().iter())
                .chain(j.to_le_bytes().iter())
                .cloned()
                .collect(),
            Op::LdI(f) => vec![4].iter()
                .chain(f.to_bytes().iter())
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
    pub ops: Vec<Op<Field>>,
    /// Number of field elements for a circuit input.
    pub inp_size: usize,
}

impl<Field: FiniteField> Ckt<Field> {
    /// Create a new circuit from a circuit size and a sequence of operations.
    pub fn new(inp_size: usize, ops: &[Op<Field>]) -> Self {
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
                Op::Sub(n, m) => out.push(out[n] - out[m]),
                Op::Div(n, m) => out.push(out[n] / out[m]),
                Op::LdI(f)    => out.push(f),
            }
        }

        out
    }
}

/// Produce a simple test circuit, as well as an input that should cause it
/// to output zero.
#[cfg(test)]
pub fn test_ckt_zero<Field>() -> (Ckt<Field>, Vec<Field>)
    where Field: FiniteField + From<u64>
{
    let ckt = Ckt::new(4,
            &vec![ // \w x y z -> x*w + y/w - 5*z
                // reg[0] <- w
                // reg[1] <- x
                // reg[2] <- y
                // reg[3] <- z
                Op::Mul(1, 0),              // reg[4]  <- x * w
                Op::Div(2, 0),              // reg[5]  <- y / w
                Op::Add(4, 5),              // reg[6]  <- (x*w) + (y/w)
                Op::LdI(Field::from(5)),    // reg[7]  <- 5
                Op::Mul(7, 3),              // reg[8]  <- 5 * z
                Op::Sub(6, 8),              // reg[9]  <- (x*w+y/w) - (5*z)
            ],
        );

    let (w, x, y) = (Field::from(5u64), Field::from(3u64), Field::from(25u64));
    let z = (x*w + y/w)/Field::from(5); // x*w + y/w - 5*z = 0 ==> z = (x*w + y/w)/5
    let inp = vec![w, x, y, z];

    debug_assert!(ckt.eval(&inp).last().unwrap() == &Field::ZERO);
    (ckt, inp)
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
            2 => Op::Sub(i, j),
            _ => panic!("Unreachable"),
        });
    }

    let output = Ckt::new(inp_size, &ops).eval(&w);
    w[0] = -(*output.last().unwrap());
    ops.push(Op::Add(0, inp_size+ckt_size-2));

    (Ckt::new(inp_size, &ops), w)
}

/// Generate an arbitrary circuit with the given size.
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

/// Generate an arbitrary circuit with the given size, along with an input that
/// makes it evaluate to zero.
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
        (c, w) in (2usize..50, 2usize..50).prop_flat_map(
            |(ws,cs)| arb_ckt_zero(ws,cs))
    ) {
        prop_assert_eq!(*c.eval(&w).last().unwrap(), TestField::ZERO);
    }
}

#[test]
fn test_eval() {
    let (ckt, inp) = test_ckt_zero::<TestField>();

    let w      = inp[0];
    let x      = inp[1];
    let y      = inp[2];
    let z      = inp[3];
    let xw     = x * w;
    let yw     = y / w;
    let xwyw   = xw + yw;
    let im5    = TestField::from(5u64);
    let z5     = im5 * z;
    let xwywz5 = xwyw - z5;

    let res = ckt.eval(&vec![w, x, y, z]);
    assert_eq!(res, vec![w, x, y, z, xw, yw, xwyw, im5, z5, xwywz5]);
}
