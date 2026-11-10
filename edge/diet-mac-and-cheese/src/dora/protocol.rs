use swanky_channel::Channel;
use swanky_error::Result;

use swanky_error::{ErrorKind, WrapErr};
use swanky_field::{FiniteField, IsSubFieldOf};
use swanky_party::private::{PartyPrivate, PartyPrivateCopy};

use crate::{
    DietMacAndCheese,
    dora::comm::CommittedWitness,
    mac::Mac,
    party::{Party, Prover, WhichParty},
    svole_trait::SvoleT,
    transcript::Transcript,
};

use super::{
    COMPACT_MIN, COMPACT_MUL,
    acc::{Accumulator, ComittedAcc, Trace, collapse_trace},
    comm::CommittedCrossTerms,
    disjunction::Disjunction,
    fiat_shamir,
    perm::permutation,
};

pub struct Dora<P: Party, V: IsSubFieldOf<F>, F: FiniteField, SvoleF: SvoleT<P, V, F>>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    disj: Disjunction<V>,
    init: Vec<ComittedAcc<DietMacAndCheese<P, V, F, SvoleF>>>,
    trace: Vec<Trace<DietMacAndCheese<P, V, F, SvoleF>>>,
    max_trace: usize, // maximum trace len before compactification
    transcript: Transcript,
    calls: PartyPrivateCopy<Prover, P, usize>,
    accs: PartyPrivate<Prover, P, Vec<Accumulator<V>>>, // current state of accumulator
}

impl<P: Party, V: IsSubFieldOf<F>, F: FiniteField, SvoleF: SvoleT<P, V, F>> Dora<P, V, F, SvoleF>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    pub fn new(disj: Disjunction<V>) -> Self {
        let accs = PartyPrivate::new(
            disj.clauses()
                .iter()
                .map(|rel| Accumulator::init(rel))
                .collect(),
        );
        let max_trace = std::cmp::max(disj.clauses().len() * COMPACT_MUL, COMPACT_MIN);
        Self {
            disj,
            init: vec![],
            trace: Vec::with_capacity(max_trace),
            max_trace,
            transcript: Transcript::new(),
            calls: PartyPrivateCopy::new(0),
            accs,
        }
    }

    // execute a mux over a secret clause
    //
    // returns commitments to the output
    pub fn mux(
        &mut self,
        dmc: &mut DietMacAndCheese<P, V, F, SvoleF>,
        mut wit_tape: impl Iterator<Item = V>, // witness tape
        input: &[Mac<P, V, F>],
        opt: PartyPrivateCopy<Prover, P, usize>,
        channel: &mut Channel,
    ) -> Result<Vec<Mac<P, V, F>>> {
        // check if we should compact the trace first
        if self.trace.len() >= self.max_trace {
            self.compact(dmc, channel)?;
        }

        match P::WHICH {
            WhichParty::Prover(ev) => {
                // retrieve R1CS for active clause
                let clause = self.disj.clause(opt.into_inner(ev));

                // compute extended witness for the clause
                let wit = clause.compute_witness(
                    &mut wit_tape,
                    input.iter().map(|input| input.value().into_inner(ev)),
                );
                debug_assert!(wit.check(clause), "invalid witness");

                // eat padding from witness tape
                for _ in clause.num_wit()..self.disj.num_wit() {
                    let v = wit_tape.next().expect("witness tape too short");
                    debug_assert_eq!(v, V::ZERO, "witness padding is not zero");
                }

                //compute cross terms with accumulator
                debug_assert!(self.accs.as_ref().into_inner(ev)[opt.into_inner(ev)].check(clause));
                let cxt = clause
                    .cross_wit_acc(&wit, &self.accs.as_ref().into_inner(ev)[opt.into_inner(ev)]);

                // commit to extended witness
                let comm_wit = CommittedWitness::commit(
                    channel,
                    &mut self.transcript,
                    dmc,
                    &self.disj,
                    input.iter().copied(),
                    PartyPrivate::new(&wit),
                )?;
                debug_assert_eq!(comm_wit.value(ev, clause), wit);

                // commit to cross terms
                let comm_cxt = CommittedCrossTerms::commit(
                    channel,
                    &mut self.transcript,
                    dmc,
                    &self.disj,
                    PartyPrivate::new(&cxt),
                )?;

                // commit to old accumulator
                let comm_acc = ComittedAcc::commit(
                    channel,
                    &mut self.transcript,
                    dmc,
                    &self.disj,
                    &self.accs.as_ref().map(|accs| &accs[opt.into_inner(ev)]),
                )?;
                debug_assert!(self.accs.as_ref().into_inner(ev)[opt.into_inner(ev)].check(clause));
                debug_assert_eq!(
                    &comm_acc.value(ev, clause),
                    &self.accs.as_ref().into_inner(ev)[opt.into_inner(ev)]
                );

                // fold extended witness, accumulator and cross terms
                let challenge = self.transcript.challenge();
                let comm_acc_new = comm_acc.fold_witness(dmc, challenge, &comm_cxt, &comm_wit)?;

                // store new accumulator
                self.accs.as_mut().into_inner(ev)[opt.into_inner(ev)] =
                    comm_acc_new.value(ev, clause);
                debug_assert!(self.accs.as_ref().into_inner(ev)[opt.into_inner(ev)].check(clause));

                // add to trace (for permutation proof)
                self.trace.push(Trace {
                    old: comm_acc,
                    new: comm_acc_new,
                });

                *self.calls.as_mut().into_inner(ev) += 1;

                // returns the outpus from the extended witness
                Ok(comm_wit.outputs().to_owned())
            }
            WhichParty::Verifier(ev) => {
                // commit to new extended witness
                let wit = CommittedWitness::commit(
                    channel,
                    &mut self.transcript,
                    dmc,
                    &self.disj,
                    input.iter().copied(),
                    PartyPrivate::empty(ev),
                )?;

                // commit to cross terms
                let cxt = CommittedCrossTerms::commit(
                    channel,
                    &mut self.transcript,
                    dmc,
                    &self.disj,
                    PartyPrivate::empty(ev),
                )?;

                // commit to old accumulator
                let acc_old = ComittedAcc::commit(
                    channel,
                    &mut self.transcript,
                    dmc,
                    &self.disj,
                    &PartyPrivate::empty(ev),
                )?;

                // fold
                let challenge = self.transcript.challenge();
                let acc_new = acc_old.fold_witness(dmc, challenge, &cxt, &wit)?;

                // update trace
                self.trace.push(Trace {
                    old: acc_old,
                    new: acc_new,
                });

                Ok(wit.outputs().to_vec())
            }
        }
    }

    /// Verify all the final accumulators using MacAndCheese
    pub fn finalize(
        mut self,
        dmc: &mut DietMacAndCheese<P, V, F, SvoleF>,
        channel: &mut Channel,
    ) -> Result<()>
    where
        F::PrimeField: IsSubFieldOf<V>,
    {
        if let WhichParty::Prover(ev) = P::WHICH {
            log::info!(
                "finalizing Dora proof: {} calls (of dimension {}) to disjunction of {} clauses",
                self.calls.into_inner(ev),
                self.disj.dim_ext(),
                self.disj.clauses().len(),
            );
        }

        // compact trace into single set of accumulators
        self.compact(dmc, channel)?;

        // verify accumulators
        for (acc, r1cs) in self.init.into_iter().zip(self.disj.clauses()) {
            acc.verify(dmc, r1cs, channel)?;
        }
        Ok(())
    }

    // "compact" the disjunction trace (without verification)
    //
    // Commits to all the accumulators and executes the permutation proof.
    // This reduces the trace to a single element per branch.
    fn compact(
        &mut self,
        dmc: &mut DietMacAndCheese<P, V, F, SvoleF>,
        channel: &mut Channel,
    ) -> Result<()> {
        let mut accs = Vec::with_capacity(self.disj.clauses().len());
        match P::WHICH {
            WhichParty::Prover(ev) => {
                for acc in self.accs.as_ref().into_inner(ev).iter() {
                    accs.push(ComittedAcc::commit(
                        channel,
                        &mut self.transcript,
                        dmc,
                        &self.disj,
                        &PartyPrivate::new(acc),
                    )?);
                }
            }
            WhichParty::Verifier(ev) => {
                for _ in self.disj.clauses() {
                    accs.push(ComittedAcc::commit(
                        channel,
                        &mut self.transcript,
                        dmc,
                        &self.disj,
                        &PartyPrivate::empty(ev),
                    )?);
                }
            }
        }

        // challenges for permutation proof
        let (chal_perm, chal_cmbn) = if fiat_shamir::<V>() {
            (self.transcript.challenge(), self.transcript.challenge())
        } else {
            match P::WHICH {
                WhichParty::Prover(_) => {
                    channel
                        .force_flush()
                        .wrap_err(ErrorKind::NetworkError, "Failed to flush channel.")?;
                    (channel.read::<V>()?, channel.read::<V>()?)
                }
                WhichParty::Verifier(_) => {
                    let chal_perm = V::random(&mut dmc.rng);
                    let chal_cmbn = V::random(&mut dmc.rng);
                    channel.write(&chal_perm)?;
                    channel.write(&chal_cmbn)?;
                    channel
                        .force_flush()
                        .wrap_err(ErrorKind::NetworkError, "Failed to flush channel.")?;
                    (chal_perm, chal_cmbn)
                }
            }
        };

        // collapse trace into single elements
        let (mut lhs, mut rhs) = collapse_trace(dmc, &self.trace, chal_cmbn)?;

        // add initial / final accumulator to permutation proof
        for (i, (acc, r1cs)) in accs.iter().zip(self.disj.clauses()).enumerate() {
            lhs.push(acc.combine(dmc, chal_cmbn)?);
            rhs.push(match self.init.get(i) {
                Some(acc) => acc.combine(dmc, chal_cmbn)?,
                None => Accumulator::init(r1cs).combine(dmc, chal_cmbn)?,
            });
        }

        // execute permutation proof
        self.trace.clear();
        self.init = accs;
        permutation(dmc, chal_perm, &lhs, &rhs, channel)
    }
}
