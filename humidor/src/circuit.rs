#[cfg(test)]
use proptest::prelude::*;

//
// XXX: Use a silly field for now.
//
type Field = crate::f2_19x3_26::F;

#[derive(Debug, Clone, Copy)]
pub enum Op { Add(usize, usize), Mul(usize, usize) }

// TODO: Add LDI, SUB, and DIV instructions.
#[cfg(test)]
impl Arbitrary for Op {
    type Parameters = usize;
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with(wires: Self::Parameters) -> Self::Strategy {
        let add = ((..wires),(..wires)).prop_map(|(i,j)| Op::Add(i,j));
        let mul = ((..wires),(..wires)).prop_map(|(i,j)| Op::Mul(i,j));
        prop_oneof![add, mul].boxed()
    }
}

#[derive(Debug, Clone)]
pub struct Ckt {
    pub ops: Vec<Op>,
    pub inp_size: usize,
}

#[cfg(test)]
impl Arbitrary for Ckt {
    type Parameters = (usize, usize);
    type Strategy = BoxedStrategy<Self>;
    fn arbitrary_with((wires, gates): Self::Parameters) -> Self::Strategy {
        if gates == 0 {
            any::<()>().prop_map(move |()| Ckt {
                ops: vec![],
                inp_size: wires,
            }).boxed()
        } else {
            let arb_c = Ckt::arbitrary_with((wires, gates - 1));
            let arb_op = Op::arbitrary_with(wires + gates - 1);
            (arb_c,arb_op).prop_map(|(Ckt {mut ops, inp_size}, op)| {
                ops.push(op);
                Ckt { ops, inp_size }
            }).boxed()
        }
    }
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

#[test]
fn test_eval1() {
    let w    = 3.into();
    let x    = 5.into();
    let y    = 7.into();
    let z    = 11.into();
    let wy   = 21.into();  // w * y
    let xz   = 55.into();  // x * z
    let wyxz = 76.into();  // w*y + x*z
    let res  = Ckt::test_value().eval(&vec![w, x, y, z]);
    assert_eq!(res, vec![w, x, y, z, wy, xz, wyxz]);
}
