use std::ops::{Add, Mul, Sub};

use eyre::Result;
use scuttlebutt::field::FiniteField;

use crate::{backend_trait::BackendT, circuit_ir::WireCount};

use super::{acc::Accumulator, DisjGate};

// position in extended witness fixed to 1
const CONSTANT_IDX: usize = 0;

#[derive(Debug, Clone, Default)]
struct LinComb<F: FiniteField>(Vec<(usize, F)>);

// Invariant: shorted by index
fn merge<F: FiniteField, OP: Fn(F, F) -> F>(
    lhs: &LinComb<F>,
    rhs: &LinComb<F>,
    f: OP,
) -> LinComb<F> {
    let mut comb = Vec::new();
    let mut i = 0;
    let mut j = 0;

    // merge terms
    while i < lhs.0.len() && j < rhs.0.len() {
        let (idx_a, a) = lhs.0[i];
        let (idx_b, b) = rhs.0[j];
        if idx_a == idx_b {
            comb.push((idx_a, f(a, b)));
            i += 1;
            j += 1;
        } else if idx_a < idx_b {
            comb.push((idx_a, a));
            i += 1;
        } else {
            comb.push((idx_b, b));
            j += 1;
        }
    }

    // copy remaining terms
    for i in i..lhs.0.len() {
        comb.push(lhs.0[i])
    }

    // copy remaining terms
    for j in j..rhs.0.len() {
        comb.push(rhs.0[j])
    }

    comb.shrink_to_fit();
    LinComb(comb)
}

impl<F: FiniteField> Add for LinComb<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        merge(&self, &rhs, |a, b| a + b)
    }
}

impl<F: FiniteField> Sub for LinComb<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        merge(&self, &rhs, |a, b| a - b)
    }
}

impl<F: FiniteField> Mul<F> for LinComb<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        let mut comb = Vec::new();
        for (idx, coeff) in self.0 {
            comb.push((idx, coeff * rhs));
        }
        LinComb(comb)
    }
}

impl<F: FiniteField> LinComb<F> {
    pub fn constant(c: F) -> Self {
        LinComb(vec![(CONSTANT_IDX, c)])
    }

    pub fn eval(&self, w: &[F]) -> F {
        let mut comb = F::zero();
        for (idx, coeff) in self.0.iter().copied() {
            comb += coeff * w[idx];
        }
        comb
    }

    pub fn eval_commit<B: BackendT<FieldElement = F>>(
        &self,
        backend: &mut B,
        w: &[B::Wire],
    ) -> Result<B::Wire> {
        // first term
        let mut entries = self.0.iter().copied();
        let (idx, coeff) = match entries.next() {
            Some(entry) => entry,
            None => {
                return backend.input_public(F::ZERO);
            }
        };
        let mut comb = backend.mul_constant(&w[idx], coeff)?;

        // all other terms
        for (idx, coeff) in entries {
            let prod = backend.mul_constant(&w[idx], coeff)?;
            comb = backend.add(&comb, &prod)?;
        }

        Ok(comb)
    }
}

#[derive(Debug, Clone)]
pub(super) struct Row<F: FiniteField> {
    l: LinComb<F>,
    r: LinComb<F>,
    o: LinComb<F>,
}

impl<F: FiniteField> Row<F> {
    pub(crate) fn eval(&self, wit: &[F]) -> (F, F, F) {
        (self.l.eval(wit), self.r.eval(wit), self.o.eval(wit))
    }

    pub(crate) fn eval_commit<B: BackendT<FieldElement = F>>(
        &self,
        backend: &mut B,
        wit: &[B::Wire],
    ) -> Result<(B::Wire, B::Wire, B::Wire)> {
        let l = self.l.eval_commit(backend, wit)?;
        let r = self.r.eval_commit(backend, wit)?;
        let o = self.o.eval_commit(backend, wit)?;
        Ok((l, r, o))
    }
}

#[derive(Debug, Clone)]
pub(super) struct R1CS<F: FiniteField> {
    pub dim: usize,
    pub cells: usize,
    pub input: usize,
    pub output: usize,
    pub gates: Vec<DisjGate<F>>, // used for witness computation
    pub rows: Vec<Row<F>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ExtendedWitness<F: FiniteField> {
    pub(super) inputs: usize,
    pub(super) outputs: usize,
    // [1 || output || input || inp ]
    pub(super) wit: Vec<F>,
}

impl<F: FiniteField> ExtendedWitness<F> {
    pub(super) fn outputs(&self) -> impl Iterator<Item = &F> {
        self.wit[1..=self.outputs].iter()
    }

    pub(super) fn intermediate(&self) -> impl Iterator<Item = &F> {
        self.wit[1 + self.outputs + self.inputs..].iter()
    }

    pub(super) fn check(&self, r1cs: &R1CS<F>) -> bool {
        if r1cs.dim() != self.wit.len() {
            return false;
        }
        for row in r1cs.rows.iter() {
            let (l, r, o) = row.eval(&self.wit);
            if l * r != o {
                return false;
            }
        }
        true
    }
}

pub(super) struct CrossTerms<F: FiniteField> {
    pub(crate) terms: Vec<F>,
}

impl<F: FiniteField> R1CS<F> {
    pub(crate) fn rows(&self) -> usize {
        self.rows.len()
    }

    pub(crate) fn dim(&self) -> usize {
        self.dim
    }

    /// Dimension of the witness (dimension excluding the constant term and input)
    pub(crate) fn dim_wit(&self) -> usize {
        assert!(self.dim > 0);
        assert!(self.dim > self.input);
        self.dim - self.input - 1
    }

    // converts a circuit into a R1CS relation
    pub(crate) fn new(input: WireCount, output: WireCount, gates: &[DisjGate<F>]) -> Self {
        assert!(input > 0, "no inputs");

        // compute the number of cells required for witness generation
        let max_cell = gates
            .iter()
            .copied()
            .map(|gate| match gate {
                DisjGate::Mul(dst, ..)
                | DisjGate::Add(dst, ..)
                | DisjGate::Sub(dst, ..)
                | DisjGate::AddConstant(dst, ..)
                | DisjGate::MulConstant(dst, ..)
                | DisjGate::AssertZero(dst, ..)
                | DisjGate::AssertConstant(dst, ..)
                | DisjGate::Copy(dst, ..)
                | DisjGate::Witness(dst)
                | DisjGate::Constant(dst, ..) => dst,
            })
            .max()
            .unwrap_or(0);

        let num_cells = std::cmp::max(max_cell + 1, (input + output) as usize);

        // allocate cells for symbolic evaluation of circuit
        let mut cells = Vec::with_capacity(num_cells);
        cells.extend((0..output).map(|_| LinComb::default()));
        cells.extend((0..input).map(|i| LinComb(vec![((1 + i + output) as usize, F::ONE)])));
        cells.resize(num_cells, LinComb::default());

        // compute constraints
        let mut cs = Vec::with_capacity(max_cell);
        let mut dim = (1 + input + output) as usize;
        for gate in gates.iter().copied() {
            match gate {
                DisjGate::Mul(dst, l, r) => {
                    let l = cells[l].clone();
                    let r = cells[r].clone();
                    let o = LinComb(vec![(dim, F::ONE)]);
                    cells[dst] = o.clone();
                    cs.push(Row { l, r, o });
                    dim += 1;
                }
                DisjGate::Copy(dst, src) => {
                    cells[dst] = cells[src].clone();
                }
                DisjGate::Witness(dst) => {
                    cells[dst] = LinComb(vec![(dim, F::ONE)]);
                    dim += 1;
                }
                DisjGate::Constant(dst, val) => {
                    cells[dst] = LinComb(vec![(CONSTANT_IDX, val)]);
                }
                DisjGate::Add(dst, l, r) => {
                    cells[dst] = cells[l].clone() + cells[r].clone();
                }
                DisjGate::Sub(dst, l, r) => {
                    cells[dst] = cells[l].clone() - cells[r].clone();
                }
                DisjGate::AddConstant(dst, l, c) => {
                    cells[dst] = cells[l].clone() + LinComb::constant(c);
                }
                DisjGate::MulConstant(dst, l, c) => {
                    cells[dst] = cells[l].clone() * c;
                }
                DisjGate::AssertZero(src) => {
                    cs.push(Row {
                        l: cells[src].clone(),
                        r: LinComb(vec![(CONSTANT_IDX, F::ONE)]),
                        o: LinComb(vec![]),
                    });
                }
                // used to easily implement the guards for clauses
                DisjGate::AssertConstant(src, val) => {
                    cs.push(Row {
                        l: cells[src].clone(),
                        r: LinComb(vec![(CONSTANT_IDX, F::ONE)]),
                        o: LinComb(vec![(CONSTANT_IDX, val)]),
                    });
                }
            }
        }

        // add output asserts
        // (if an output is unassigned it is set to 0)
        for src in 0..(output as usize) {
            cs.push(Row {
                l: cells[src].clone(),
                r: LinComb(vec![(CONSTANT_IDX, F::ONE)]),
                o: LinComb(vec![(src + 1, F::ONE)]),
            });
        }

        cs.shrink_to_fit();

        Self {
            dim,
            input: input as usize,
            output: output as usize,
            cells: num_cells,
            gates: gates.to_vec(),
            rows: cs,
        }
    }

    pub fn compute_witness<I: Iterator<Item = F>>(&self, input: I) -> ExtendedWitness<F> {
        // copy input to cells (for evaluation)
        // [1 || output || input]
        let mut cells = Vec::with_capacity(self.cells);
        cells.extend((0..self.output).map(|_| F::ZERO));
        cells.extend(input);
        debug_assert_eq!(cells.len(), self.input + self.output);

        // alloc space for [ output || input ]
        let mut wit = Vec::with_capacity(self.dim);
        wit.push(F::ONE);
        wit.extend_from_slice(&cells[..]);

        // allocate temp cells for evaluation
        cells.resize(self.cells, F::ZERO);
        debug_assert_eq!(cells.len(), self.cells);

        // compute output (and intermediate witness values)
        for gate in self.gates.iter().copied() {
            match gate {
                DisjGate::Mul(dst, lhs, rhs) => {
                    let res = cells[lhs] * cells[rhs];
                    wit.push(res);
                    cells[dst] = res;
                }
                DisjGate::Copy(dst, src) => {
                    cells[dst] = cells[src];
                }
                DisjGate::Constant(dst, val) => {
                    cells[dst] = val;
                }
                DisjGate::Add(dst, lhs, rhs) => {
                    cells[dst] = cells[lhs] + cells[rhs];
                }
                DisjGate::Sub(dst, l, r) => {
                    cells[dst] = cells[l] - cells[r];
                }
                DisjGate::AddConstant(dst, src, c) => {
                    cells[dst] = cells[src] + c;
                }
                DisjGate::MulConstant(dst, src, c) => {
                    cells[dst] = cells[src] * c;
                }
                DisjGate::AssertConstant(src, val) => {
                    assert_eq!(
                        cells[src], val,
                        "assert equal in disjunction not satisified"
                    );
                }
                DisjGate::AssertZero(src) => {
                    assert_eq!(cells[src], F::ZERO, "assert zero in disjunction failed");
                }
                DisjGate::Witness(_dst) => {
                    // this should just assign a cell freely
                    // but we need to pass in the witness tape somehow.
                    unimplemented!("not implemented (yet)")
                }
            }
        }

        // copy outputs to witness
        wit[1..=self.output].copy_from_slice(&cells[..self.output]);

        // wrap in extended witness
        let ext = ExtendedWitness {
            wit,
            inputs: self.input,
            outputs: self.output,
        };

        // sanity check: R1CS relation is sat.
        debug_assert!(ext.check(self), "{:#?}", ext);
        ext
    }

    fn cross_terms(&self, wit1: &[F], wit2: &[F]) -> CrossTerms<F> {
        debug_assert_eq!(wit1.len(), self.dim);
        debug_assert_eq!(wit2.len(), self.dim);

        // compute u1 * z1 - u2 * z2
        // (to reduce number of matrix multiplications)
        let u1 = wit1[CONSTANT_IDX];
        let u2 = wit2[CONSTANT_IDX];
        let mut u1z1_u2z2 = Vec::with_capacity(self.dim);
        for (z1, z2) in wit1.iter().copied().zip(wit2.iter().copied()) {
            u1z1_u2z2.push(u1 * z2 + u2 * z1);
        }

        // compute err cross terms
        let mut terms = Vec::with_capacity(self.rows());
        terms.extend(self.rows.iter().map(|row| {
            let a_z1 = row.l.eval(wit1);
            let a_z2 = row.l.eval(wit2);
            let b_z1 = row.r.eval(wit1);
            let b_z2 = row.r.eval(wit2);
            let c_z1z2 = row.o.eval(&u1z1_u2z2);
            a_z1 * b_z2 + a_z2 * b_z1 - c_z1z2
        }));
        CrossTerms { terms }
    }

    pub(crate) fn cross_wit_acc(
        &self,
        wit: &ExtendedWitness<F>,
        acc: &Accumulator<F>,
    ) -> CrossTerms<F> {
        debug_assert_eq!(wit.wit.len(), self.dim);
        debug_assert_eq!(acc.wit.len(), self.dim);
        debug_assert_eq!(acc.err.len(), self.rows.len());
        self.cross_terms(&wit.wit, &acc.wit)
    }
}
