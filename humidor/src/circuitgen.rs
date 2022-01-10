//! This module implements helper functions for generating random arithmetic
//! circuits.

use crate::circuit::{Circuit, Index, Op};
use rand::{
    distributions::{Distribution, Uniform},
    Rng,
};
use scuttlebutt::field::FiniteField;

#[cfg(test)]
use crate::util::{arb_test_field, TestField};
#[cfg(test)]
use proptest::{collection::vec as pvec, prelude::*};

fn rand_ix_pair(rng: &mut impl Rng, min: Index, max: Index) -> (Index, Index) {
    debug_assert!(max - min > 1);

    let s = max - min;

    let a = rng.gen_range(0, s);
    let b = rng.gen_range(1, s);

    (min + a, min + (a + b) % s)
}

/// Pick an operation at random, for random test circuits.
pub fn random_op<Field>(rng: &mut impl Rng, min_wire: Index, max_wire: Index) -> Op<Field>
where
    Field: FiniteField,
{
    let coin = Uniform::from(0..4);
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

/// Output a random circuit with an input that evaluates to 0. Both inp_size and
/// ckt_size must be at least 2.
pub fn random_ckt_zero<Field: FiniteField>(
    rng: &mut impl Rng,
    inp_size: usize,
    ckt_size: usize,
) -> (Circuit<Field>, Vec<Field>) {
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
    let output = Circuit::new(inp_size, ops.clone(), None).eval(&w);
    ops.push(Op::LdI(*output.last().unwrap()));
    ops.push(Op::Sub(inp_size + ckt_size - 2, inp_size + ckt_size - 3));

    (Circuit::new(inp_size, ops, None), w)
}

#[cfg(test)]
fn arb_ix_pair(min: Index, max: Index) -> impl Strategy<Value = (Index, Index)> {
    debug_assert!(max - min > 1);

    let s = max - min;
    (0..s, 1..s).prop_map(move |(a, b)| (min + a, min + (a + b) % s))
}

#[cfg(test)]
pub fn arb_op<Field>(wire_min: Index, wire_max: Index) -> impl Strategy<Value = Op<Field>>
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

/// Produce a simple test circuit, as well as an input that should cause it
/// to output zero.
#[cfg(test)]
pub fn test_ckt_zero<Field>() -> (Circuit<Field>, Vec<Field>)
where
    Field: FiniteField + From<u64>,
{
    let ckt = Circuit::new(
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
        None,
    );

    let (w, x, y) = (Field::from(5u64), Field::from(3u64), Field::from(25u64));
    let z = (x * w + y / w) / Field::from(5); // x*w + y/w - 5*z = 0 ==> z = (x*w + y/w)/5
    let inp = vec![w, x, y, z];

    debug_assert!(ckt.eval(&inp).last().unwrap() == &Field::ZERO);
    (ckt, inp)
}

/// Generate an arbitrary circuit with at most the given size.
#[cfg(test)]
#[allow(unused)]
pub fn arb_ckt(inp_size: usize, ckt_size: usize) -> impl Strategy<Value = Circuit<TestField>> {
    debug_assert!(inp_size > 1);
    debug_assert!(ckt_size > 0);

    (1..ckt_size)
        .into_iter()
        .fold(pvec(arb_op(0, inp_size), 1).boxed(), |acc, c| {
            (acc, arb_op(0, inp_size + c))
                .prop_map(|(ops, op)| ops.into_iter().chain(std::iter::once(op)).collect())
                .boxed()
        })
        .prop_map(move |ops| Circuit {
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
) -> impl Strategy<Value = (Circuit<TestField>, Vec<TestField>)> {
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
        let (c, w): (Circuit<TestField>, Vec<_>) = random_ckt_zero(&mut rng, inp_size, ckt_size);

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
