use eyre::Result;

use scuttlebutt::{field::FiniteField, ring::FiniteRing, AbstractChannel};
use swanky_field::IsSubFieldOf;

use crate::{backend_trait::BackendT, DietMacAndCheeseProver};

use super::{
    comm::{CommittedCrossTerms, CommittedWitness},
    disjunction::Disjunction,
    r1cs::R1CS,
};

pub(super) struct ComittedAcc<B: BackendT> {
    pub wit: Vec<B::Wire>, // commitment to witness
    pub err: Vec<B::Wire>, // commitment to error term
}

pub(super) struct Trace<B: BackendT> {
    pub old: ComittedAcc<B>,
    pub new: ComittedAcc<B>,
}

pub(super) fn collapse_trace<B: BackendT>(
    backend: &mut B,
    trace: &[Trace<B>],
    x: B::FieldElement,
) -> Result<(Vec<B::Wire>, Vec<B::Wire>)> {
    let mut lhs = Vec::with_capacity(trace.len() + 1);
    let mut rhs = Vec::with_capacity(trace.len() + 1);
    for tr in trace {
        lhs.push(tr.old.combine(backend, x)?);
        rhs.push(tr.new.combine(backend, x)?);
    }
    Ok((lhs, rhs))
}

impl<B: BackendT> ComittedAcc<B> {
    /// Verify a committed accumulator using the underlaying proof system
    ///
    /// The accumulator may have junk at the end (which is not verfied)
    /// for an honest prover this junk will be zero, however it is
    /// not required to enforce this for soundness.
    pub fn verify(&self, backend: &mut B, r1cs: &R1CS<B::FieldElement>) -> Result<()> {
        if self.wit.len() < r1cs.dim() {
            return Err(eyre::eyre!("witness dimension too small"));
        }

        if self.err.len() < r1cs.rows() {
            return Err(eyre::eyre!("error dimension to small"));
        }

        let u = &self.wit[0];

        for (row, err) in r1cs.rows.iter().zip(self.err.iter()) {
            let (l, r, o) = row.eval_commit(backend, &self.wit)?;
            let m = backend.mul(&l, &r)?;
            let t = backend.mul(&o, u)?;
            let m = backend.sub(&m, &t)?;
            let m = backend.sub(&m, err)?;
            backend.assert_zero(&m)?;
        }

        Ok(())
    }

    pub fn combine(&self, backend: &mut B, x: B::FieldElement) -> Result<B::Wire> {
        let mut cs = self.wit.iter().chain(self.err.iter());
        let mut y: B::Wire = backend.copy(cs.next().unwrap())?;
        for c in cs {
            y = backend.mul_constant(&y, x)?;
            y = backend.add(&y, c)?;
        }
        Ok(y)
    }

    pub fn fold_witness(
        &self,
        backend: &mut B,
        chl: <B as BackendT>::FieldElement,
        cxt: &CommittedCrossTerms<B>,
        wit: &CommittedWitness<B>,
    ) -> Result<Self> {
        debug_assert_eq!(self.err.len(), cxt.terms.len());
        debug_assert_eq!(self.wit.len(), wit.wit.len());

        let mut nerr = Vec::with_capacity(self.err.len());
        let mut nwit = Vec::with_capacity(self.wit.len());

        // err' = err + r * T
        for (e, t) in self.err.iter().zip(cxt.terms.iter()) {
            let r = backend.mul_constant(t, chl)?;
            let r = backend.add(&r, e)?;
            nerr.push(r);
        }

        // wit' = r * wit2 + wit1
        for (w1, w2) in self.wit.iter().zip(wit.wit.iter()) {
            let r = backend.mul_constant(w2, chl)?;
            let r = backend.add(&r, w1)?;
            nwit.push(r);
        }

        Ok(Self {
            wit: nwit,
            err: nerr,
        })
    }

    pub fn new<'a>(
        backend: &mut B,
        disj: &Disjunction<B::FieldElement>,
        acc: Option<&Accumulator<B::FieldElement>>,
    ) -> Result<Self> {
        let mut wit = Vec::with_capacity(disj.dim_wit());
        let mut err = Vec::with_capacity(disj.dim_err());

        let zero = <<B as BackendT>::FieldElement as FiniteRing>::ZERO;

        match acc {
            Some(acc) => {
                debug_assert!(acc.wit.len() <= disj.dim_ext());
                debug_assert!(acc.err.len() <= disj.dim_err());
                for i in 0..disj.dim_ext() {
                    let w = acc.wit.get(i).unwrap_or(&zero);
                    wit.push(backend.input_private(Some(*w))?);
                }
                for i in 0..disj.dim_err() {
                    let e = acc.err.get(i).unwrap_or(&zero);
                    err.push(backend.input_private(Some(*e))?);
                }
            }
            None => {
                for _ in 0..disj.dim_ext() {
                    wit.push(backend.input_private(None)?);
                }
                for _ in 0..disj.dim_err() {
                    err.push(backend.input_private(None)?);
                }
            }
        }

        // check that it pads the length to hide the active branch
        debug_assert_eq!(wit.len(), disj.dim_ext());
        debug_assert_eq!(err.len(), disj.dim_err());

        Ok(ComittedAcc { wit, err })
    }
}

impl<V: IsSubFieldOf<F>, F: FiniteField, C: AbstractChannel>
    ComittedAcc<DietMacAndCheeseProver<V, F, C>>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    pub fn value(&self, clause: &R1CS<V>) -> Accumulator<V> {
        let mut wit = Vec::with_capacity(clause.dim());
        let mut err = Vec::with_capacity(clause.rows());

        debug_assert!(self.wit.len() >= clause.dim());
        debug_assert!(self.err.len() >= clause.rows());

        for i in 0..clause.dim() {
            wit.push(self.wit[i].value());
        }

        for i in 0..clause.rows() {
            err.push(self.err[i].value());
        }

        let acc = Accumulator { wit, err };
        acc
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
// Nova-style accumulator
pub(super) struct Accumulator<F: FiniteField> {
    pub wit: Vec<F>, // extended witness
    pub err: Vec<F>, // error term
}

impl<F: FiniteField> Accumulator<F> {
    // Computes an arbitrary fixed accumulator
    // in the acculuation language defined by the R1CS relation
    pub(crate) fn init(rel: &R1CS<F>) -> Self {
        // the extended witness is fixed to zero, the constant is zero, everything is linear
        let acc = Self {
            wit: vec![F::zero(); rel.dim()],
            err: vec![F::zero(); rel.rows()],
        };
        debug_assert!(acc.check(rel));
        acc
    }
}

impl<F: FiniteField> Accumulator<F> {
    // Checks membership of the accumulator language.
    //
    // Note the lack of constant (1) check. This is intentional.
    pub(crate) fn check(&self, r1cs: &R1CS<F>) -> bool {
        if r1cs.rows() != self.err.len() {
            return false;
        }

        if r1cs.dim() != self.wit.len() {
            return false;
        }

        let u = self.wit[0];

        for (row, err) in r1cs.rows.iter().zip(self.err.iter().copied()) {
            let (l, r, o) = row.eval(&self.wit);
            if l * r != u * o + err {
                return false;
            }
        }
        true
    }

    pub fn send<C: AbstractChannel>(&self, chan: &mut C) -> Result<()> {
        for w in self.wit.iter() {
            chan.write_serializable(w)?;
        }
        for e in self.err.iter() {
            chan.write_serializable(e)?;
        }
        Ok(())
    }

    pub fn recv<C: AbstractChannel>(chan: &mut C, r1cs: &R1CS<F>) -> Result<Self> {
        let mut wit = Vec::with_capacity(r1cs.dim());
        let mut err = Vec::with_capacity(r1cs.rows());

        for _ in 0..r1cs.dim() {
            wit.push(chan.read_serializable()?);
        }

        for _ in 0..r1cs.rows() {
            err.push(chan.read_serializable()?);
        }

        let acc = Self { wit, err };
        debug_assert!(acc.check(r1cs));
        Ok(acc)
    }

    pub fn combine<B: BackendT<FieldElement = F>>(
        &self,
        backend: &mut B,
        x: B::FieldElement,
    ) -> Result<B::Wire> {
        let mut cs = self.wit.iter().chain(self.err.iter()).copied();
        let mut y = cs.next().unwrap();
        for c in cs {
            y = y * x;
            y = y + c;
        }
        backend.input_public(y)
    }
}
