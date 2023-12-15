use scuttlebutt::field::FiniteField;

// handling of (FS) transcripts
mod tx;

// handling of R1CS accumulators
mod acc;

// disjunction type
mod disjunction;

// conversion from circuit_ir to R1CS
mod r1cs;

// "commited" versions of various types
mod comm;

// permutation proof
mod perm;

// Dora
mod protocol;

type WireId = usize;

pub use disjunction::Disjunction;
pub use protocol::Dora;
use swanky_field::PrimeFiniteField;

use crate::circuit_ir::{GateM, TypeId};

use generic_array::typenum::Unsigned;

// We periodically compact the trace to ensure a constant memory consumption.
//
// Making this a multiple of the number of clauses ensures that the
// asymptotic cost of a disjunction is the cost of a single clause
const COMPACT_MUL: usize = 10;
const COMPACT_MIN: usize = 1000;

fn fiat_shamir<F: FiniteField>() -> bool {
    <F as FiniteField>::NumberOfBitsInBitDecomposition::to_usize() > 100
}

// a restricted set of gates possible in clauses
#[derive(Debug, Clone, Copy)]
enum DisjGate<F: FiniteField> {
    // translation of supported GateM variants
    Add(WireId, WireId, WireId),
    Sub(WireId, WireId, WireId),
    Mul(WireId, WireId, WireId),
    Copy(WireId, WireId),
    // not yet supported
    Witness(WireId),
    Constant(WireId, F),
    AddConstant(WireId, WireId, F),
    MulConstant(WireId, WireId, F),
    AssertZero(WireId),
    // convenient for implementing the guard
    AssertConstant(WireId, F),
}

#[derive(Debug, Clone)]
pub struct Clause<F: FiniteField> {
    gates: Vec<DisjGate<F>>,
}

impl<F: PrimeFiniteField> Clause<F> {
    /// also acts as a sanitizer to verify that only disjunction safe gates are used
    ///
    /// It add gates to enforce the guard for each clause,
    /// pushing the guard inputs at the end
    ///
    /// The input to the disjunction is [input || cond]
    /// where cond is not exposed to the body of the clause.
    pub(crate) fn new(
        typ: TypeId,
        inputs: usize, // inputs to clause (body, not including guard/cond)
        outputs: usize,
        guard: &[F],     // guard value
        gates: &[GateM], // body
    ) -> Self {
        // translate gates
        let mut body = Vec::with_capacity(gates.len());

        // push gates to check guard
        // note: these cells may subsequently be used by the body
        {
            let off = inputs + outputs;
            for (idx, val) in guard.iter().copied().enumerate() {
                body.push(DisjGate::AssertConstant(off + idx, val));
            }
        }

        // translate body
        for gate in gates.iter().cloned() {
            translate_gate(&mut body, typ, gate);
        }

        Clause { gates: body }
    }
}

fn tidx(w: u64) -> usize {
    w as usize
}

// Translates `gate` to one or more `DisjGate`, pushing the result(s) to
// `disj_gates`. Checks that all gates are for `typ`.
fn translate_gate<F: PrimeFiniteField>(
    disj_gates: &mut Vec<DisjGate<F>>,
    typ: TypeId,
    gate: GateM,
) {
    match gate {
        GateM::Add(typ2, dst, lhs, rhs) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            disj_gates.push(DisjGate::Add(tidx(dst), tidx(lhs), tidx(rhs)))
        }
        GateM::Sub(typ2, dst, lhs, rhs) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            disj_gates.push(DisjGate::Sub(tidx(dst), tidx(lhs), tidx(rhs)))
        }
        GateM::Mul(typ2, dst, lhs, rhs) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            disj_gates.push(DisjGate::Mul(tidx(dst), tidx(lhs), tidx(rhs)))
        }
        GateM::Copy(typ2, dst, src) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            let mut curr_out = dst.0;
            for curr_input_range in *src {
                for curr_inp in curr_input_range.0..=curr_input_range.1 {
                    disj_gates.push(DisjGate::Copy(tidx(curr_out), tidx(curr_inp)));
                    curr_out += 1;
                }
            }
        }
        GateM::Witness(typ2, dst) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            for curr_dst in dst.0..=dst.1 {
                disj_gates.push(DisjGate::Witness(tidx(curr_dst)))
            }
        }
        GateM::Constant(typ2, dst, cnst) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            let val = F::try_from_int(*cnst).unwrap();
            disj_gates.push(DisjGate::Constant(tidx(dst), val))
        }
        GateM::AddConstant(typ2, dst, src, cnst) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            let val = F::try_from_int(*cnst).unwrap();
            disj_gates.push(DisjGate::AddConstant(tidx(dst), tidx(src), val))
        }
        GateM::MulConstant(typ2, dst, src, cnst) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            let val = F::try_from_int(*cnst).unwrap();
            disj_gates.push(DisjGate::MulConstant(tidx(dst), tidx(src), val))
        }
        GateM::AssertZero(typ2, src) => {
            assert_eq!(typ2, typ, "different types in disjunction");
            disj_gates.push(DisjGate::AssertZero(tidx(src)))
        }
        GateM::New(_, _, _) | GateM::Comment(_) => {}
        _ => panic!("unsupported gate: {:?}", gate),
    }
}
