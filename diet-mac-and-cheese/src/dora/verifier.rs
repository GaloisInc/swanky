use eyre::Result;
use scuttlebutt::{field::FiniteField, AbstractChannel};
use swanky_field::IsSubFieldOf;

use crate::{
    dora::{comm::CommittedCrossTerms, tx::TxChannel},
    mac::MacVerifier,
    svole_trait::SvoleT,
    DietMacAndCheeseVerifier,
};

use super::{
    acc::{collapse_trace, Accumulator, ComittedAcc, Trace},
    comm::CommittedWitness,
    disjunction::Disjunction,
    perm::permutation,
};

pub struct DoraVerifier<V: IsSubFieldOf<F>, F: FiniteField, C: AbstractChannel, SVOLE: SvoleT<F>>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    _ph: std::marker::PhantomData<(F, C)>,
    disj: Disjunction<V>,
    trace: Vec<Trace<DietMacAndCheeseVerifier<V, F, C, SVOLE>>>,
    tx: blake3::Hasher,
}

impl<V: IsSubFieldOf<F>, F: FiniteField, C: AbstractChannel, SVOLE: SvoleT<F>>
    DoraVerifier<V, F, C, SVOLE>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    pub fn new(disj: Disjunction<V>) -> Self {
        Self {
            _ph: std::marker::PhantomData,
            trace: vec![],
            disj,
            tx: blake3::Hasher::new(),
        }
    }

    pub fn mux(
        &mut self,
        verifier: &mut DietMacAndCheeseVerifier<V, F, C, SVOLE>,
        input: &[MacVerifier<F>],
    ) -> Result<Vec<MacVerifier<F>>> {
        // wrap channel in transcript
        let mut ch = TxChannel::new(verifier.channel.clone(), &mut self.tx);

        // commit to new extended witness
        let wit =
            CommittedWitness::commit_verifer(&mut ch, verifier, &self.disj, input.iter().copied())?;

        // commit to cross terms
        let cxt = CommittedCrossTerms::commit_verifier(&mut ch, verifier, &self.disj)?;

        // commit to old accumulator
        let acc_old = ComittedAcc::commit_verifier(&mut ch, verifier, &self.disj)?;

        // fold
        let challenge = ch.challenge();
        let acc_new = acc_old.fold_witness(verifier, challenge, &cxt, &wit)?;

        // update trace
        self.trace.push(Trace {
            old: acc_old,
            new: acc_new,
        });

        Ok(wit.outputs().to_vec())
    }

    /// Verifies all the disjuctions and consumes the verifier.
    pub fn finalize(self, verifier: &mut DietMacAndCheeseVerifier<V, F, C, SVOLE>) -> Result<()> {
        // commit and verify all final accumulators
        let mut accs = Vec::with_capacity(self.disj.clauses().len());
        for r1cs in self.disj.clauses() {
            let acc = ComittedAcc::new(verifier, &self.disj, None)?;
            acc.verify(verifier, r1cs)?;
            accs.push(acc);
        }

        // challenges for permutation proof
        let chal_perm = V::random(&mut verifier.rng);
        let chal_cmbn = V::random(&mut verifier.rng);
        verifier.channel.write_serializable(&chal_perm)?;
        verifier.channel.write_serializable(&chal_cmbn)?;
        verifier.channel.flush()?;

        // collapse trace into single elements
        let (mut lhs, mut rhs) = collapse_trace(verifier, &self.trace, chal_cmbn)?;

        // verify first/final accumulators
        for (acc, r1cs) in accs.iter_mut().zip(self.disj.clauses()) {
            // add initial / final accumulator to permutation proof
            lhs.push(acc.combine(verifier, chal_cmbn)?);
            rhs.push(Accumulator::init(r1cs).combine(verifier, chal_cmbn)?);
        }

        // execute permutation proof
        permutation(verifier, chal_perm, &lhs, &rhs)
    }
}
