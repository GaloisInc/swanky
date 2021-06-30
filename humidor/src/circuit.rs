use rand::{Rng, distributions::{Distribution, Uniform}};
use scuttlebutt::field::FiniteField;

#[cfg(test)]
use proptest::{*, prelude::*, collection::vec as pvec};

use crate::util::random_field_array;

// TODO: Add LDI, SUB, and DIV instructions.
#[derive(Debug, Clone, Copy)]
pub enum Op { Add(usize, usize), Mul(usize, usize) }

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

#[derive(Debug, Clone)]
pub struct Ckt<Field> {
    phantom: std::marker::PhantomData<Field>,

    pub ops: Vec<Op>,
    pub inp_size: usize,
}

impl<Field: FiniteField> Ckt<Field> {
    pub fn new(inp_size: usize, ops: &[Op]) -> Self {
        Self {
            phantom: std::marker::PhantomData,
            ops: ops.to_vec(),
            inp_size,
        }
    }

    pub fn size(&self) -> usize { self.ops.len() + self.inp_size }

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

// Output a random circuit with an input that evaluates to 0. Both inp_size and
// ckt_size must be at least 2.
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
pub fn arb_ckt<Field: FiniteField>(
    inp_size: usize,
    ckt_size: usize
) -> impl Strategy<Value = Ckt<Field>> {
    if ckt_size == 0 {
        any::<()>().prop_map(move |()| Ckt::new(inp_size, &vec![])).boxed()
    } else {
        let arb_c = arb_ckt(inp_size, ckt_size - 1);
        let arb_op = arb_op(0, inp_size + ckt_size - 1);
        (arb_c,arb_op).prop_map(|(Ckt::<Field> {phantom, mut ops, inp_size}, op)| {
            ops.push(op);
            <Ckt<Field>>::new(inp_size, &ops)
        }).boxed()
    }
}

#[cfg(test)]
#[allow(unused)]
fn arb_ckt_with_inp_hole<Field: FiniteField>(
    inp_size: usize,
    ckt_size: usize,
) -> impl Strategy<Value = Ckt<Field>> {
    if ckt_size == 0 {
        any::<()>().prop_map(move |()| Ckt {
            phantom: std::marker::PhantomData,
            ops: vec![],
            inp_size,
        }).boxed()
    } else {
        let arb_c = arb_ckt_with_inp_hole(inp_size, ckt_size - 1);
        let arb_op = arb_op(1, inp_size + ckt_size - 1);
        (arb_c,arb_op).prop_map(|(Ckt::<Field> {phantom, mut ops, inp_size}, op)| {
            ops.push(op);
            <Ckt<Field>>::new(inp_size, &ops)
        }).boxed()
    }
}

// XXX: See comment on arb_ckt, above.
#[cfg(test)]
pub fn arb_ckt_zero<Field: FiniteField + proptest::arbitrary::Arbitrary>(
    inp_size: usize,
    ckt_size: usize,
) -> impl Strategy<Value = (Ckt<Field>, Vec<Field>)> {
    (
        arb_ckt_with_inp_hole(inp_size, ckt_size-1),
        pvec(any::<Field>(), inp_size),
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
        let (c, w): (Ckt<crate::f2_19x3_26::F>, Vec<_>)
                     = random_ckt_zero(&mut rng, inp_size, ckt_size);

        assert_eq!(*c.eval(&w).last().unwrap(), crate::f2_19x3_26::F::ZERO);
    }
}

#[cfg(test)]
proptest! {
    #[test]
    fn test_arb_ckt_zero(
        (c, w) in (2usize..100, 2usize..100).prop_flat_map(
            |(ws,cs)| arb_ckt_zero::<crate::f2_19x3_26::F>(ws,cs))
    ) {
        prop_assert_eq!(*c.eval(&w).last().unwrap(), crate::f2_19x3_26::F::ZERO);
    }
}

#[test]
fn test_eval() {
    let w    = crate::f2_19x3_26::F::from(3u64);
    let x    = crate::f2_19x3_26::F::from(5u64);
    let y    = crate::f2_19x3_26::F::from(7u64);
    let z    = crate::f2_19x3_26::F::from(11u64);
    let wy   = crate::f2_19x3_26::F::from(21u64);  // w * y
    let xz   = crate::f2_19x3_26::F::from(55u64);  // x * z
    let wyxz = crate::f2_19x3_26::F::from(76u64);  // w*y + x*z
    let res  = Ckt::test_value().eval(&vec![w, x, y, z]);
    assert_eq!(res, vec![w, x, y, z, wy, xz, wyxz]);
}
