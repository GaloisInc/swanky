use rand::Rng;

#[cfg(test)]
use proptest::{*, prelude::*, collection::vec as pvec};

use crate::util::random_field_array;

//
// XXX: Use a silly field for now.
//
type Field = crate::f2_19x3_26::F;

// TODO: Add LDI, SUB, and DIV instructions.
#[derive(Debug, Clone, Copy)]
pub enum Op { Add(usize, usize), Mul(usize, usize) }

pub fn random_op(rng: &mut impl Rng, s: usize) -> Op {
    match rng.gen_range(0usize..2) {
        0 => Op::Add(rng.gen_range(0..s), rng.gen_range(0..s)),
        1 => Op::Mul(rng.gen_range(0..s), rng.gen_range(0..s)),
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

#[derive(Debug, Clone)]
pub struct Ckt {
    pub ops: Vec<Op>,
    pub inp_size: usize,
}

impl Ckt {
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
        Self {
            inp_size: 4,
            ops: vec![ // \w x y z -> w*y + x*z
                Op::Mul(0, 2),
                Op::Mul(1, 3),
                Op::Add(4, 5),
            ],
        }
    }
}

// Output a random circuit with an input that evaluates to 0. Both inp_size and
// ckt_size must be at least 2.
pub fn random_ckt_zero(
    mut rng: impl Rng,
    inp_size: usize,
    ckt_size: usize
) -> (Ckt, Vec<Field>) {
    debug_assert!(inp_size > 1);
    debug_assert!(ckt_size > 1);

    let mut w: Vec<Field> = random_field_array(&mut rng, inp_size).to_vec();
    let mut ops = vec![];
    for n in 0 .. ckt_size-1 {
        let i = rng.gen_range(1 .. inp_size + n);
        let j = rng.gen_range(1 .. inp_size + n);

        ops.push(match rng.gen_range(0usize..2) {
            0 => Op::Add(i, j),
            1 => Op::Mul(i, j),
            _ => panic!("Unreachable"),
        });
    }

    let output = (Ckt {ops: ops.clone(), inp_size}).eval(&w);
    w[0] = output.last().unwrap().neg();
    ops.push(Op::Add(0, inp_size+ckt_size-2));

    (Ckt {ops, inp_size}, w)
}

// XXX: This is a bad way to do this. Creating large circuits will overflow
// the stack. Need to figure out something better, maybe along the lines of
// this: https://altsysrq.github.io/proptest-book/proptest/tutorial/recursive.html
#[cfg(test)]
pub fn arb_ckt(inp_size: usize, ckt_size: usize) -> impl Strategy<Value = Ckt> {
    if ckt_size == 0 {
        any::<()>().prop_map(move |()| Ckt {
            ops: vec![],
            inp_size,
        }).boxed()
    } else {
        let arb_c = arb_ckt(inp_size, ckt_size - 1);
        let arb_op = arb_op(0, inp_size + ckt_size - 1);
        (arb_c,arb_op).prop_map(|(Ckt {mut ops, inp_size}, op)| {
            ops.push(op);
            Ckt { ops, inp_size }
        }).boxed()
    }
}

#[cfg(test)]
fn arb_ckt_with_inp_hole(
    inp_size: usize,
    ckt_size: usize,
) -> impl Strategy<Value = Ckt> {
    if ckt_size == 0 {
        any::<()>().prop_map(move |()| Ckt {
            ops: vec![],
            inp_size,
        }).boxed()
    } else {
        let arb_c = arb_ckt_with_inp_hole(inp_size, ckt_size - 1);
        let arb_op = arb_op(1, inp_size + ckt_size - 1);
        (arb_c,arb_op).prop_map(|(Ckt {mut ops, inp_size}, op)| {
            ops.push(op);
            Ckt { ops, inp_size }
        }).boxed()
    }
}

// XXX: See comment on arb_ckt, above.
#[cfg(test)]
pub fn arb_ckt_zero(
    inp_size: usize,
    ckt_size: usize,
) -> impl Strategy<Value = (Ckt, Vec<Field>)> {
    (
        arb_ckt_with_inp_hole(inp_size, ckt_size-1),
        pvec(any::<Field>(), inp_size),
    ).prop_map(move |(mut c, mut w)| {
        let output = c.eval(&w);
        w[0] = output.last().unwrap().neg();
        c.ops.push(Op::Add(0, inp_size+ckt_size-2));

        (c, w)
    })
}

#[test]
fn test_random_ckt_zero() {
    use rand::{SeedableRng, rngs::StdRng};

    let mut rng = StdRng::from_entropy();

    for _ in 0..1000 {
        let inp_size = rng.gen_range(2..1000);
        let ckt_size = rng.gen_range(2..1000);
        let (c, w) = random_ckt_zero(&mut rng, inp_size, ckt_size);

        assert_eq!(*c.eval(&w).last().unwrap(), Field::ZERO);
    }
}

#[cfg(test)]
proptest! {
    #[test]
    fn test_arb_ckt_zero(
        (c, w) in (2usize..100, 2usize..100).prop_flat_map(
            |(ws,cs)| arb_ckt_zero(ws,cs))
    ) {
        prop_assert_eq!(*c.eval(&w).last().unwrap(), Field::ZERO);
    }
}

#[test]
fn test_eval() {
    let w    = 3u64.into();
    let x    = 5u64.into();
    let y    = 7u64.into();
    let z    = 11u64.into();
    let wy   = 21u64.into();  // w * y
    let xz   = 55u64.into();  // x * z
    let wyxz = 76u64.into();  // w*y + x*z
    let res  = Ckt::test_value().eval(&vec![w, x, y, z]);
    assert_eq!(res, vec![w, x, y, z, wy, xz, wyxz]);
}
