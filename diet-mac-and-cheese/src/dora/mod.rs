use std::collections::HashMap;

use scuttlebutt::{field::FiniteField, AbstractChannel};

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
pub(crate) mod perm;

// Dora
mod protocol;

#[cfg(test)]
mod tests;

// conversion from circuit_ir to disjunction
mod translate;

type WireId = usize;

pub use disjunction::Disjunction;
pub use protocol::Dora;
use swanky_field::IsSubFieldOf;
use swanky_party::{private::ProverPrivate, Party};
use translate::translate;

use crate::{
    circuit_ir::{FunStore, GateM, TypeId},
    fields::SieveIrDeserialize,
    svole_trait::SvoleT,
};

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
// note: this is a "cell machine" which may assign to the same cell multiple times
// (unlike the circuit_ir which should not)
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

impl<F: FiniteField + SieveIrDeserialize> Clause<F> {
    /// also acts as a sanitizer to verify that only disjunction safe gates are used
    ///
    /// It add gates to enforce the guard for each clause,
    /// pushing the guard inputs at the end
    ///
    /// The input to the disjunction is [input || cond]
    /// where cond is not exposed to the body of the clause.
    pub(crate) fn new(
        typ: TypeId,
        fun_store: &FunStore,
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
        translate(
            inputs,
            outputs,
            &mut body,
            fun_store,
            typ,
            gates.iter().cloned(),
        );

        body.shrink_to_fit();
        Clause { gates: body }
    }
}

pub struct DoraState<
    P: Party,
    V: IsSubFieldOf<F>,
    F: FiniteField,
    C: AbstractChannel + Clone,
    SvoleF: SvoleT<P, V, F>,
> where
    F::PrimeField: IsSubFieldOf<V>,
{
    // map used to lookup the guard -> active clause index
    pub clause_resolver: ProverPrivate<P, HashMap<F, usize>>,
    // dora for this particular switch/mux
    pub dora: Dora<P, V, F, C, SvoleF>,
}
