use std::cmp;

use scuttlebutt::field::FiniteField;
use swanky_field::PrimeFiniteField;

use crate::{circuit_ir::WireCount, plugins::DisjunctionBody};

use super::{r1cs::R1CS, Clause};

#[derive(Debug, Clone)]
pub struct Disjunction<F: FiniteField> {
    dim_wit: usize,        // dimension of witness vector
    dim_err: usize,        // dimension of error vector
    inputs: usize,         // number of inputs to disjunction
    outputs: usize,        // number of outputs from disjunction
    clauses: Vec<R1CS<F>>, // R1CS relations for each clause
}

impl<FP: PrimeFiniteField> Disjunction<FP> {
    pub fn compile(disj: &DisjunctionBody) -> Self {
        Self::new(
            disj.clauses().map(|cls| {
                let guard = FP::try_from_int(cls.guard).unwrap();
                Clause::new(
                    disj.field(),
                    disj.inputs() as usize,
                    disj.outputs() as usize,
                    &[guard],
                    cls.body.gates(),
                )
            }),
            disj.inputs() + disj.cond(),
            disj.outputs(),
        )
    }
}

impl<F: FiniteField> Disjunction<F> {
    pub fn new<I: Iterator<Item = Clause<F>>>(
        clauses: I,
        inputs: WireCount,
        outputs: WireCount,
    ) -> Self {
        // convert every clause to R1CS
        let mut dim_wit = 0;
        let mut dim_err = 0;
        let mut r1cs_rels = vec![];
        for opt in clauses {
            let rel = R1CS::new(inputs, outputs, &opt.gates);
            dim_wit = cmp::max(dim_wit, rel.dim_wit());
            dim_err = cmp::max(dim_err, rel.rows());
            r1cs_rels.push(rel);
        }

        // "compile" gates to R1CS relations
        Self {
            dim_err,
            dim_wit,
            inputs: inputs as usize,
            outputs: outputs as usize,
            clauses: r1cs_rels,
        }
    }

    pub(super) fn clauses(&self) -> &[R1CS<F>] {
        &self.clauses
    }

    pub(super) fn clause(&self, idx: usize) -> &R1CS<F> {
        &self.clauses[idx]
    }

    pub fn dim_wit(&self) -> usize {
        self.dim_wit
    }

    pub fn dim_err(&self) -> usize {
        self.dim_err
    }

    pub fn dim_input(&self) -> usize {
        self.inputs
    }

    pub fn dim_output(&self) -> usize {
        self.outputs
    }

    pub fn dim_intermediate(&self) -> usize {
        self.dim_wit() - self.outputs
    }

    pub fn dim_ext(&self) -> usize {
        1 + self.inputs + self.dim_wit
    }

    pub fn inputs(&self) -> usize {
        self.inputs
    }

    pub fn outputs(&self) -> usize {
        self.outputs
    }
}
