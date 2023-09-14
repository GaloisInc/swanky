use eyre::Result;
use scuttlebutt::{field::FiniteField, ring::FiniteRing, AbstractChannel, AesRng};
use std::iter;
use swanky_field::IsSubFieldOf;
use swanky_party::{
    either::PartyEitherCopy, private::ProverPrivateCopy, Prover, Verifier, IS_PROVER, IS_VERIFIER,
};

use crate::{
    backend_trait::BackendT, homcom::FCom, mac::Mac, svole_trait::SvoleT, DietMacAndCheeseProver,
    DietMacAndCheeseVerifier,
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
// (allows control of the channel for Fiat-Shamir)
//
// Idealy there would be a nicer way to do this.
fn prover_commit_vec<
    'a,
    V: IsSubFieldOf<F>,
    F: FiniteField,
    C: AbstractChannel,
    SvoleFSender: SvoleT<(V, F)>,
    SvoleFReceiver: SvoleT<F>,
>(
    backend: &mut FCom<Prover, V, F, SvoleFSender, SvoleFReceiver>,
    channel: &mut C,
    rng: &mut AesRng,
    sec: impl IntoIterator<Item = V>, // secret values
    len: usize,                       // padded length
) -> Result<impl Iterator<Item = Mac<Prover, V, F>>>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    // commit to remaining (padded)
    let mut pad = Vec::with_capacity(len);
    pad.extend(sec.into_iter().chain(iter::repeat(V::ZERO)).take(len));

    // mac vector
    let tag = backend
        .input(channel, rng, PartyEitherCopy::prover_new(IS_PROVER, &pad))?
        .prover_into(IS_PROVER);

    // combine
    Ok(tag
        .into_iter()
        .zip(pad.into_iter())
        .map(|(t, v)| Mac::new(ProverPrivateCopy::new(v), t)))
}

fn verifier_commit_vec<
    'a,
    V: IsSubFieldOf<F>,
    F: FiniteField,
    C: AbstractChannel,
    SvoleFSender: SvoleT<(V, F)>,
    SvoleFReceiver: SvoleT<F>,
>(
    backend: &mut FCom<Verifier, V, F, SvoleFSender, SvoleFReceiver>,
    channel: &mut C,
    rng: &mut AesRng,
    len: usize, // padded length
) -> Result<impl Iterator<Item = Mac<Verifier, V, F>>>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    let inp = backend
        .input(
            channel,
            rng,
            PartyEitherCopy::verifier_new(IS_VERIFIER, len),
        )?
        .verifier_into(IS_VERIFIER);
    Ok(inp.into_iter())
}

impl<
        'a,
        V: IsSubFieldOf<F>,
        F: FiniteField,
        C: AbstractChannel,
        SvoleFSender: SvoleT<(V, F)>,
        SvoleFReceiver: SvoleT<F>,
    > CommittedWitness<'a, DietMacAndCheeseProver<V, F, C, SvoleFSender, SvoleFReceiver>>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    pub fn commit_prover<
        'b,
        I: Iterator<Item = <DietMacAndCheeseProver<V, F, C, SvoleFSender, SvoleFReceiver> as BackendT>::Wire>,
    >(
        channel: &mut impl AbstractChannel,
        backend: &mut DietMacAndCheeseProver<V, F, C, SvoleFSender, SvoleFReceiver>,
        disj: &'a Disjunction<V>,
        input: I,
        witness: &'b ExtendedWitness<V>,
    ) -> Result<Self>{
        // commit to witness
        let out = witness.outputs().copied();
        let int = witness.intermediate().copied();
        let free = prover_commit_vec(
            &mut backend.prover,
            channel,
            &mut backend.rng,
            out.chain(int),
            disj.dim_output() + disj.dim_intermediate(),
        )?;
        Self::from_parts(backend, disj, input, free)
    }
}

impl<
        'a,
        V: IsSubFieldOf<F>,
        F: FiniteField,
        C: AbstractChannel,
        SvoleFSender: SvoleT<(V, F)>,
        SvoleFReceiver: SvoleT<F>,
    > CommittedWitness<'a, DietMacAndCheeseVerifier<V, F, C, SvoleFSender, SvoleFReceiver>>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    pub fn commit_verifer<
        'b,
        I: Iterator<Item = <DietMacAndCheeseVerifier<V, F, C, SvoleFSender, SvoleFReceiver> as BackendT>::Wire>,
    >(
        channel: &mut impl AbstractChannel,
        backend: &mut DietMacAndCheeseVerifier<V, F, C, SvoleFSender, SvoleFReceiver>,
        disj: &'a Disjunction<V>,
        input: I,
    ) -> Result<Self>{
        // commit to witness
        let free = verifier_commit_vec(
            &mut backend.verifier,
            channel,
            &mut backend.rng,
            disj.dim_output() + disj.dim_intermediate(),
        )?;
        Self::from_parts(backend, disj, input, free)
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

impl<
        'a,
        V: IsSubFieldOf<F>,
        F: FiniteField,
        C: AbstractChannel,
        SvoleFSender: SvoleT<(V, F)>,
        SvoleFReceiver: SvoleT<F>,
    > CommittedWitness<'a, DietMacAndCheeseProver<V, F, C, SvoleFSender, SvoleFReceiver>>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    pub fn value(&self, clause: &R1CS<V>) -> ExtendedWitness<V> {
        let mut wit = Vec::with_capacity(clause.dim());
        debug_assert!(self.wit.len() >= clause.dim());
        for i in 0..clause.dim() {
            wit.push(self.wit[i].value(IS_PROVER));
        }
        ExtendedWitness {
            inputs: clause.input,
            outputs: clause.output,
            wit,
        }
    }
}

pub(super) struct CommittedCrossTerms<B: BackendT> {
    pub terms: Vec<B::Wire>,
}

impl<
        'a,
        V: IsSubFieldOf<F>,
        F: FiniteField,
        C: AbstractChannel,
        SvoleFSender: SvoleT<(V, F)>,
        SvoleFReceiver: SvoleT<F>,
    > CommittedCrossTerms<DietMacAndCheeseProver<V, F, C, SvoleFSender, SvoleFReceiver>>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    pub fn commit_prover<'b>(
        channel: &mut impl AbstractChannel,
        backend: &mut DietMacAndCheeseProver<V, F, C, SvoleFSender, SvoleFReceiver>,
        disj: &'a Disjunction<V>,
        cxt: &CrossTerms<V>,
    ) -> Result<Self> {
        let mut terms = Vec::with_capacity(disj.dim_err());
        terms.extend(prover_commit_vec(
            &mut backend.prover,
            channel,
            &mut backend.rng,
            cxt.terms.iter().copied(),
            disj.dim_err(),
        )?);
        Ok(Self { terms })
    }
}

impl<
        'a,
        V: IsSubFieldOf<F>,
        F: FiniteField,
        C: AbstractChannel,
        SvoleFSender: SvoleT<(V, F)>,
        SvoleFReceiver: SvoleT<F>,
    > CommittedCrossTerms<DietMacAndCheeseVerifier<V, F, C, SvoleFSender, SvoleFReceiver>>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    pub fn commit_verifier<'b>(
        channel: &mut impl AbstractChannel,
        backend: &mut DietMacAndCheeseVerifier<V, F, C, SvoleFSender, SvoleFReceiver>,
        disj: &'a Disjunction<V>,
    ) -> Result<Self> {
        let mut terms = Vec::with_capacity(disj.dim_err());
        terms.extend(verifier_commit_vec(
            &mut backend.verifier,
            channel,
            &mut backend.rng,
            disj.dim_err(),
        )?);
        Ok(Self { terms })
    }
}

impl<
        V: IsSubFieldOf<F>,
        F: FiniteField,
        C: AbstractChannel,
        SvoleFSender: SvoleT<(V, F)>,
        SvoleFReceiver: SvoleT<F>,
    > ComittedAcc<DietMacAndCheeseProver<V, F, C, SvoleFSender, SvoleFReceiver>>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    pub fn commit_prover<'a>(
        channel: &mut impl AbstractChannel,
        backend: &mut DietMacAndCheeseProver<V, F, C, SvoleFSender, SvoleFReceiver>,
        disj: &'a Disjunction<V>,
        acc: &Accumulator<V>,
    ) -> Result<Self> {
        let wit = prover_commit_vec(
            &mut backend.prover,
            channel,
            &mut backend.rng,
            acc.wit.iter().copied(),
            disj.dim_ext(),
        )?
        .collect();

        let err = prover_commit_vec(
            &mut backend.prover,
            channel,
            &mut backend.rng,
            acc.err.iter().copied(),
            disj.dim_err(),
        )?
        .collect();

        Ok(Self { wit, err })
    }
}

impl<
        'a,
        V: IsSubFieldOf<F>,
        F: FiniteField,
        C: AbstractChannel,
        SvoleFSender: SvoleT<(V, F)>,
        SvoleFReceiver: SvoleT<F>,
    > ComittedAcc<DietMacAndCheeseVerifier<V, F, C, SvoleFSender, SvoleFReceiver>>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    pub fn commit_verifier<'b>(
        channel: &mut impl AbstractChannel,
        backend: &mut DietMacAndCheeseVerifier<V, F, C, SvoleFSender, SvoleFReceiver>,
        disj: &'a Disjunction<V>,
    ) -> Result<Self> {
        let wit = verifier_commit_vec(
            &mut backend.verifier,
            channel,
            &mut backend.rng,
            disj.dim_ext(),
        )?
        .collect();

        let err = verifier_commit_vec(
            &mut backend.verifier,
            channel,
            &mut backend.rng,
            disj.dim_err(),
        )?
        .collect();

        Ok(Self { wit, err })
    }
}
