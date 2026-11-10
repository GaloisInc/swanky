use std::iter;
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::{FiniteField, FiniteRing, IsSubFieldOf};
use swanky_party::{
    private::{PartyPrivate, PartyPrivateCopy},
    ty_eq::{EqualityProposition, Witness},
};
use swanky_rng::SwankyRng;

use crate::{
    DietMacAndCheese,
    backend_trait::BackendT,
    homcom::FCom,
    mac::Mac,
    party::{Party, Prover, WhichParty},
    svole_trait::SvoleT,
    transcript::Transcript,
};

use super::{
    acc::{Accumulator, ComittedAcc},
    disjunction::Disjunction,
    r1cs::{CrossTerms, ExtendedWitness, R1CS},
};

#[derive(Debug)]
pub(super) struct CommittedWitness<'a, B: BackendT> {
    disj: &'a Disjunction<B::FieldElement>,
    pub wit: Vec<B::Wire>,
}

// Low-level commit to vector
fn commit_vec<
    P: Party,
    V: IsSubFieldOf<F>,
    F: FiniteField,
    I: IntoIterator<Item = V>,
    SvoleF: SvoleT<P, V, F>,
>(
    backend: &mut FCom<P, V, F, SvoleF>,
    channel: &mut Channel,
    rng: &mut SwankyRng,
    transcript: &mut Transcript,
    sec: PartyPrivate<Prover, P, I>, // secret values
    len: usize,                      // padded length
) -> Result<impl Iterator<Item = Mac<P, V, F>> + use<P, V, F, I, SvoleF>>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    match P::WHICH {
        WhichParty::Prover(ev) => {
            // commit to remaining (padded)
            let mut pad = Vec::with_capacity(len);
            pad.extend(
                sec.into_inner(ev)
                    .into_iter()
                    .chain(iter::repeat(V::ZERO))
                    .take(len),
            );

            // mac vector
            let tag = backend.input_prover_with_transcript(ev, channel, rng, &pad, transcript)?;

            // combine
            Ok(tag
                .into_iter()
                .zip(pad)
                .map(|(t, v)| Mac::new(PartyPrivateCopy::new(v), t))
                .collect::<Vec<_>>()
                .into_iter())
        }
        WhichParty::Verifier(ev) => {
            let inp = backend.input_verifier_with_transcript(ev, channel, rng, len, transcript)?;
            Ok(inp.into_iter())
        }
    }
}

impl<'a, P: Party, V: IsSubFieldOf<F>, F: FiniteField, SvoleF: SvoleT<P, V, F>>
    CommittedWitness<'a, DietMacAndCheese<P, V, F, SvoleF>>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    pub fn commit<'b, I: Iterator<Item = <DietMacAndCheese<P, V, F, SvoleF> as BackendT>::Wire>>(
        channel: &mut Channel,
        transcript: &mut Transcript,
        backend: &mut DietMacAndCheese<P, V, F, SvoleF>,
        disj: &'a Disjunction<V>,
        input: I,
        witness: PartyPrivate<Prover, P, &'b ExtendedWitness<V>>,
    ) -> Result<Self> {
        let free = commit_vec(
            &mut backend.fcom,
            channel,
            &mut backend.rng,
            transcript,
            witness.map(|witness| {
                witness
                    .outputs()
                    .copied()
                    .chain(witness.intermediate().copied())
            }),
            disj.dim_output() + disj.dim_intermediate(),
        )?;
        Self::from_parts(backend, disj, input, free)
    }

    pub fn value(
        &self,
        ev: Witness<impl EqualityProposition<P, Prover>>,
        clause: &R1CS<V>,
    ) -> ExtendedWitness<V> {
        let mut wit = Vec::with_capacity(clause.dim());
        debug_assert!(self.wit.len() >= clause.dim());
        for i in 0..clause.dim() {
            wit.push(self.wit[i].value().into_inner(ev.sym()));
        }
        ExtendedWitness {
            inputs: clause.input,
            outputs: clause.output,
            wit,
        }
    }
}

impl<'a, B: BackendT> CommittedWitness<'a, B> {
    fn from_parts(
        backend: &mut B,
        disj: &'a Disjunction<B::FieldElement>,
        input: impl Iterator<Item = B::Wire>,
        mut free: impl Iterator<Item = B::Wire>,
    ) -> Result<Self> {
        // constant
        let mut wit = Vec::with_capacity(disj.dim_ext());
        wit.push(backend.input_public(<B as BackendT>::FieldElement::ONE)?);

        // output
        for _ in 0..disj.outputs() {
            wit.push(free.next().unwrap());
        }

        // input
        wit.extend(input);

        // intermediate wires
        wit.extend(free);

        debug_assert_eq!(wit.len(), disj.dim_ext());

        Ok(Self { disj, wit })
    }

    pub fn outputs(&self) -> &[B::Wire] {
        let out = self.wit[1..=self.disj.dim_output()].as_ref();
        debug_assert_eq!(out.len(), self.disj.dim_output());
        out
    }
}

pub(super) struct CommittedCrossTerms<B: BackendT> {
    pub terms: Vec<B::Wire>,
}

impl<P: Party, V: IsSubFieldOf<F>, F: FiniteField, SvoleF: SvoleT<P, V, F>>
    CommittedCrossTerms<DietMacAndCheese<P, V, F, SvoleF>>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    pub fn commit(
        channel: &mut Channel,
        transcript: &mut Transcript,
        backend: &mut DietMacAndCheese<P, V, F, SvoleF>,
        disj: &Disjunction<V>,
        cxt: PartyPrivate<Prover, P, &CrossTerms<V>>,
    ) -> Result<Self> {
        let mut terms = Vec::with_capacity(disj.dim_err());
        terms.extend(commit_vec(
            &mut backend.fcom,
            channel,
            &mut backend.rng,
            transcript,
            cxt.map(|cxt| cxt.terms.iter().copied()),
            disj.dim_err(),
        )?);
        Ok(Self { terms })
    }
}

impl<P: Party, V: IsSubFieldOf<F>, F: FiniteField, SvoleF: SvoleT<P, V, F>>
    ComittedAcc<DietMacAndCheese<P, V, F, SvoleF>>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    pub fn commit(
        channel: &mut Channel,
        transcript: &mut Transcript,
        backend: &mut DietMacAndCheese<P, V, F, SvoleF>,
        disj: &Disjunction<V>,
        acc: &PartyPrivate<Prover, P, &Accumulator<V>>,
    ) -> Result<Self> {
        let wit = commit_vec(
            &mut backend.fcom,
            channel,
            &mut backend.rng,
            transcript,
            acc.as_ref().map(|acc| acc.wit.iter().copied()),
            disj.dim_ext(),
        )?
        .collect();

        let err = commit_vec(
            &mut backend.fcom,
            channel,
            &mut backend.rng,
            transcript,
            acc.as_ref().map(|acc| acc.err.iter().copied()),
            disj.dim_err(),
        )?
        .collect();

        Ok(Self { wit, err })
    }
}
