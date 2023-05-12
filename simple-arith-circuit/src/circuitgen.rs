//! This module implements helper functions for generating random circuits.

use crate::circuit::{Circuit, Index, Op};
use rand::{
    distributions::{Distribution, Uniform},
    Rng,
};
use scuttlebutt::field::{FiniteField, F2};
use scuttlebutt::ring::FiniteRing;

fn rand_ix_pair(rng: &mut impl Rng, min: Index, max: Index) -> (Index, Index) {
    let s = max - min;
    let a = rng.gen_range(0..s);
    let b = rng.gen_range(1..s);
    (min + a, min + (a + b) % s)
}

/// Pick an operation at random, for random test circuits.
fn random_op<F: FiniteField>(rng: &mut impl Rng, min_wire: Index, max_wire: Index) -> Op<F> {
    assert!(max_wire - min_wire > 1);
    let coin = Uniform::from(0..5);
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
        3 => Op::Constant(F::random(rng)),
        4 => Op::Copy(rng.gen_range(0..max_wire - min_wire)),
        _ => unreachable!(),
    }
}

/// Output a circuit that outputs zero given `witness` as input.
fn zero_circuit<F: FiniteField>(ninputs: usize, witness: &[F], ops: Vec<Op<F>>) -> Circuit<F> {
    assert_eq!(ninputs, witness.len());
    let circuit = Circuit::new(ninputs, 1, ops);
    let mut wires = Vec::with_capacity(circuit.nwires());
    let output = circuit.eval(witness, &mut wires)[0];
    crate::builder::add_equality_check(circuit, output)
}

/// Output a binary circuit that outputs zero given `witness` as input.
fn binary_zero_circuit(
    ninputs: usize,
    noutputs: usize,
    witness: &[F2],
    ops: Vec<Op<F2>>,
) -> Circuit<F2> {
    assert_eq!(ninputs, witness.len());
    let circuit = Circuit::new(ninputs, noutputs, ops);
    let mut wires = Vec::with_capacity(circuit.nwires());
    let outputs = circuit.eval(witness, &mut wires);
    crate::builder::add_binary_equality_check(circuit, outputs)
}

/// Output a circuit evaluating to zero that's just multiply gates.
pub fn mul_zero_circuit<F: FiniteField, R: Rng>(
    ninputs: usize,
    ngates: usize,
    rng: &mut R,
) -> (Circuit<F>, Vec<F>) {
    debug_assert!(ninputs > 1);
    debug_assert!(ngates > 2);
    let ops = (0..ngates - 2)
        .map(|c| {
            let (i, j) = rand_ix_pair(rng, 0, ninputs + c);
            Op::Mul(i, j)
        })
        .collect();
    let witness: Vec<F> = (0..ninputs).map(|_| F::random(rng)).collect();
    let circuit = zero_circuit(ninputs, &witness, ops);
    (circuit, witness)
}

/// Output a random _binary_ circuit with an input that evaluates to zero.
pub fn random_binary_zero_circuit<R: Rng>(
    ninputs: usize,
    noutputs: usize,
    ngates: usize,
    rng: &mut R,
) -> (Circuit<F2>, Vec<F2>) {
    debug_assert!(ninputs > 1);
    debug_assert!(ngates > 2);
    let ops = (0..ngates)
        .map(|c| random_op(rng, 0, ninputs + c))
        .collect();
    let witness: Vec<F2> = (0..ninputs).map(|_| F2::random(rng)).collect();
    let circuit = binary_zero_circuit(ninputs, noutputs, &witness, ops);
    (circuit, witness)
}

/// Output a random circuit with an input that evaluates to zero.
pub fn random_zero_circuit<F: FiniteField, R: Rng>(
    ninputs: usize,
    ngates: usize,
    rng: &mut R,
) -> (Circuit<F>, Vec<F>) {
    debug_assert!(ninputs > 1);
    debug_assert!(ngates > 2);
    let ops = (0..ngates)
        .map(|c| random_op(rng, 0, ninputs + c))
        .collect();
    let witness: Vec<F> = (0..ninputs).map(|_| F::random(rng)).collect();
    let circuit = zero_circuit(ninputs, &witness, ops);
    (circuit, witness)
}

/// Output a random circuit.
pub fn random_circuit<F: FiniteField, R: Rng>(
    ninputs: usize,
    ngates: usize,
    noutputs: usize,
    rng: &mut R,
) -> (Circuit<F>, Vec<F>) {
    let ops = (0..ngates)
        .map(|c| random_op(rng, 0, ninputs + c))
        .collect();
    let witness: Vec<F> = (0..ninputs).map(|_| F::random(rng)).collect();
    let circuit = Circuit::new(ninputs, noutputs, ops);
    (circuit, witness)
}

/// Produce a simple test circuit, as well as an input that should cause it
/// to output zero.
#[cfg(any(feature = "proptest", test))]
pub fn simple_test_circuit<F: PrimeFiniteField>() -> (Circuit<F>, Vec<F>) {
    let circuit = Circuit::new(
        4,
        1,
        vec![
            // \w x y z -> x*w + y*w - z
            // reg[0] <- w
            // reg[1] <- x
            // reg[2] <- y
            // reg[3] <- z
            Op::Mul(1, 0), // reg[4]  <- x * w
            Op::Mul(2, 0), // reg[5]  <- y * w
            Op::Add(4, 5), // reg[6]  <- (x*w) + (y*w)
            Op::Sub(6, 3), // reg[7]  <- (x*w+y*w) - z
        ],
    );
    let (w, x, y) = (
        F::try_from(5u128).unwrap_or_else(|_| panic!("Field too small")),
        F::try_from(5u128).unwrap_or_else(|_| panic!("Field too small")),
        F::try_from(5u128).unwrap_or_else(|_| panic!("Field too small")),
    );
    let z = x * w + y * w;
    let inputs = vec![w, x, y, z];
    let mut wires = Vec::with_capacity(circuit.nwires());
    let output = circuit.eval(&inputs, &mut wires)[0];
    assert_eq!(output, F::ZERO);
    (circuit, inputs)
}

#[cfg(any(feature = "proptest", test))]
use proptest::{collection::vec as pvec, prelude::*};
#[cfg(any(feature = "proptest", test))]
use scuttlebutt::field::PrimeFiniteField;

#[cfg(any(feature = "proptest", test))]
fn any_fe<F: FiniteField>() -> BoxedStrategy<F> {
    any::<u128>()
        .prop_map(|seed| F::from_uniform_bytes(&seed.to_le_bytes()))
        .boxed()
}

#[cfg(any(feature = "proptest", test))]
fn arb_ix(min: Index, max: Index) -> impl Strategy<Value = Index> {
    debug_assert!(max - min > 0);
    let s = max - min;
    (0..s).prop_map(move |a| min + a)
}

#[cfg(any(feature = "proptest", test))]
fn arb_ix_pair(min: Index, max: Index) -> impl Strategy<Value = (Index, Index)> {
    debug_assert!(max - min > 1);

    let s = max - min;
    (0..s, 1..s).prop_map(move |(a, b)| (min + a, min + (a + b) % s))
}

#[cfg(any(feature = "proptest", test))]
fn arb_op<F: PrimeFiniteField>(wire_min: Index, wire_max: Index) -> impl Strategy<Value = Op<F>> {
    prop_oneof![
        arb_ix_pair(wire_min, wire_max).prop_map(|(i, j)| Op::Add(i, j)),
        arb_ix_pair(wire_min, wire_max).prop_map(|(i, j)| Op::Mul(i, j)),
        arb_ix_pair(wire_min, wire_max).prop_map(|(i, j)| Op::Sub(i, j)),
        arb_ix(wire_min, wire_max).prop_map(|i| Op::Copy(i)),
        any_fe::<F>().prop_map(|f| Op::Constant(f)),
    ]
}

/// Generate an arbitrary circuit with at most the given size.
#[cfg(any(feature = "proptest", test))]
pub fn arbitrary_circuit<F: PrimeFiniteField>(
    ninputs: usize,
    ngates: usize,
) -> impl Strategy<Value = Circuit<F>> {
    debug_assert!(ninputs > 1);
    debug_assert!(ngates > 0);

    (1..ngates)
        .fold(pvec(arb_op(0, ninputs), 1).boxed(), |acc, c| {
            (acc, arb_op(0, ninputs + c))
                .prop_map(|(ops, op)| ops.into_iter().chain(std::iter::once(op)).collect())
                .boxed()
        })
        .prop_map(move |ops| Circuit::new(ninputs, 1, ops))
}

/// Generate an arbitrary circuit with the given size, along with an input that
/// makes it evaluate to zero.
#[cfg(any(feature = "proptest", test))]
pub fn arbitrary_zero_circuit<F: PrimeFiniteField>(
    ninputs: usize,
    ngates: usize,
) -> impl Strategy<Value = (Circuit<F>, Vec<F>)> {
    debug_assert!(ninputs > 1);
    debug_assert!(ngates > 2);

    (
        arbitrary_circuit(ninputs, ngates - 2),
        pvec(any_fe(), ninputs),
    )
        .prop_map(move |(c, w)| {
            let mut wires = Vec::with_capacity(c.nwires());
            let output = c.eval(&w, &mut wires)[0];
            let c = crate::builder::add_equality_check(c, output);
            (c, w)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use scuttlebutt::{AesRng, Block};

    type TestField = scuttlebutt::field::F2e19x3e26;

    fn any_seed() -> impl Strategy<Value = Block> {
        any::<u128>().prop_map(Block::from)
    }

    proptest! {
        #[test]
        fn test_random_zero_circuit(seed in any_seed()) {
            let mut rng = AesRng::from_seed(seed);
            let size = Uniform::from(3..1000);
            let ninputs = size.sample(&mut rng);
            let ngates = size.sample(&mut rng);
            let (circuit, witness): (Circuit<TestField>, Vec<_>) =
                random_zero_circuit(ninputs, ngates, &mut rng);
            let mut wires = Vec::with_capacity(circuit.nwires());
            let output = circuit.eval(&witness, &mut wires)[0];
            assert_eq!(output, TestField::ZERO);
        }
    }

    proptest! {
        #[test]
        fn test_random_binary_zero_circuit(seed in any_seed()) {
            let mut rng = AesRng::from_seed(seed);
            let inputsize = Uniform::from(2..100);
            let outputsize = Uniform::from(1..100);
            let gatesize = Uniform::from(200..1000);
            let ninputs = inputsize.sample(&mut rng);
            let noutputs = outputsize.sample(&mut rng);
            let ngates = gatesize.sample(&mut rng);
            println!("{} {} {}", ninputs, noutputs, ngates);
            let (circuit, witness): (Circuit<F2>, Vec<_>) =
                random_binary_zero_circuit(ninputs, noutputs, ngates, &mut rng);
            assert_eq!(circuit.noutputs(), 1);
            let mut wires = Vec::with_capacity(circuit.nwires());
            let output = circuit.eval(&witness, &mut wires)[0];
            assert_eq!(output, F2::ZERO);
        }
    }

    proptest! {
        #[test]
        fn test_arb_ckt_zero(
            (c, w) in (2usize..50, 3usize..50).prop_flat_map(
                |(ws,cs)| arbitrary_zero_circuit::<TestField>(ws,cs))
        ) {
            let mut wires = Vec::with_capacity(c.nwires());
            let output = c.eval(&w, &mut wires)[0];
            prop_assert_eq!(output, TestField::ZERO);
        }
    }

    #[test]
    fn test_eval() {
        let (ckt, inp) = simple_test_circuit::<TestField>();

        let w = inp[0];
        let x = inp[1];
        let y = inp[2];
        let z = inp[3];
        let xw = x * w;
        let yw = y * w;
        let xwyw = xw + yw;
        let xwywz = xwyw - z;

        let mut wires = Vec::with_capacity(ckt.nwires());
        let _ = ckt.eval(&[w, x, y, z], &mut wires);
        assert_eq!(wires, vec![w, x, y, z, xw, yw, xwyw, xwywz]);
    }
}
