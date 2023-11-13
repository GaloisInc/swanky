use eyre::Result;

use scuttlebutt::AbstractChannel;
use swanky_field::{FiniteField, IsSubFieldOf};
use swanky_party::{
    private::{ProverPrivate, ProverPrivateCopy},
    Party, WhichParty,
};

use crate::{dora::comm::CommittedWitness, mac::Mac, svole_trait::SvoleT, DietMacAndCheese};

use super::{
    acc::{collapse_trace, Accumulator, ComittedAcc, Trace},
    comm::CommittedCrossTerms,
    disjunction::Disjunction,
    fiat_shamir,
    perm::permutation,
    tx::TxChannel,
    COMPACT_MIN, COMPACT_MUL,
};

pub struct Dora<
    P: Party,
    V: IsSubFieldOf<F>,
    F: FiniteField,
    C: AbstractChannel + Clone,
    SvoleF: SvoleT<P, V, F>,
> where
    F::PrimeField: IsSubFieldOf<V>,
{
    disj: Disjunction<V>,
    init: Vec<ComittedAcc<DietMacAndCheese<P, V, F, C, SvoleF>>>,
    trace: Vec<Trace<DietMacAndCheese<P, V, F, C, SvoleF>>>,
    max_trace: usize, // maximum trace len before compactification
    tx: blake3::Hasher,
    calls: ProverPrivateCopy<P, usize>,
    accs: ProverPrivate<P, Vec<Accumulator<V>>>, // current state of accumulator
}

impl<
        P: Party,
        V: IsSubFieldOf<F>,
        F: FiniteField,
        C: AbstractChannel + Clone,
        SvoleF: SvoleT<P, V, F>,
    > Dora<P, V, F, C, SvoleF>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    pub fn new(disj: Disjunction<V>) -> Self {
        let accs = ProverPrivate::new(
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
            tx: blake3::Hasher::new(),
            calls: ProverPrivateCopy::new(0),
            accs,
        }
    }

    // execute a mux over a secret clause
    //
    // returns commitments to the output
    pub fn mux(
        &mut self,
        dmc: &mut DietMacAndCheese<P, V, F, C, SvoleF>,
        input: &[Mac<P, V, F>],
        opt: ProverPrivateCopy<P, usize>,
    ) -> Result<Vec<Mac<P, V, F>>> {
        // check if we should compact the trace first
        if self.trace.len() >= self.max_trace {
            self.compact(dmc)?;
        }

        match P::WHICH {
            WhichParty::Prover(ev) => {
                // retrieve R1CS for active clause
                let clause = self.disj.clause(opt.into_inner(ev));

                // compute extended witness for the clause
                let wit =
                    clause.compute_witness(input.iter().map(|input| input.value().into_inner(ev)));
                debug_assert!(wit.check(clause));

                //compute cross terms with accumulator
                debug_assert!(self.accs.as_ref().into_inner(ev)[opt.into_inner(ev)].check(clause));
                let cxt = clause
                    .cross_wit_acc(&wit, &self.accs.as_ref().into_inner(ev)[opt.into_inner(ev)]);

                // wrap in transcript hasher (if FS enabled)
                let mut ch = TxChannel::new(dmc.channel.clone(), &mut self.tx);

                // commit to extended witness
                let comm_wit = CommittedWitness::commit(
                    &mut ch,
                    dmc,
                    &self.disj,
                    input.iter().copied(),
                    ProverPrivate::new(&wit),
                )?;
                debug_assert_eq!(comm_wit.value(ev, clause), wit);

                // commit to cross terms
                let comm_cxt = CommittedCrossTerms::commit(
                    &mut ch,
                    dmc,
                    &self.disj,
                    ProverPrivate::new(&cxt),
                )?;

                // commit to old accumulator
                let comm_acc = ComittedAcc::commit(
                    &mut ch,
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
                let challenge = ch.challenge();
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
                // wrap channel in transcript
                let mut ch = TxChannel::new(dmc.channel.clone(), &mut self.tx);

                // commit to new extended witness
                let wit = CommittedWitness::commit(
                    &mut ch,
                    dmc,
                    &self.disj,
                    input.iter().copied(),
                    ProverPrivate::empty(ev),
                )?;

                // commit to cross terms
                let cxt = CommittedCrossTerms::commit(
                    &mut ch,
                    dmc,
                    &self.disj,
                    ProverPrivate::empty(ev),
                )?;

                // commit to old accumulator
                let acc_old =
                    ComittedAcc::commit(&mut ch, dmc, &self.disj, &ProverPrivate::empty(ev))?;

                // fold
                let challenge = ch.challenge();
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
    pub fn finalize(mut self, dmc: &mut DietMacAndCheese<P, V, F, C, SvoleF>) -> Result<()>
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
        self.compact(dmc)?;

        // verify accumulators
        for (acc, r1cs) in self.init.into_iter().zip(self.disj.clauses()) {
            acc.verify(dmc, r1cs)?;
        }
        Ok(())
    }

    // "compact" the disjunction trace (without verification)
    //
    // Commits to all the accumulators and executes the permutation proof.
    // This reduces the trace to a single element per branch.
    fn compact(&mut self, dmc: &mut DietMacAndCheese<P, V, F, C, SvoleF>) -> Result<()> {
        let mut ch = TxChannel::new(dmc.channel.clone(), &mut self.tx);
        let mut accs = Vec::with_capacity(self.disj.clauses().len());
        match P::WHICH {
            WhichParty::Prover(ev) => {
                for acc in self.accs.as_ref().into_inner(ev).iter() {
                    accs.push(ComittedAcc::commit(
                        &mut ch,
                        dmc,
                        &self.disj,
                        &ProverPrivate::new(acc),
                    )?);
                }
            }
            WhichParty::Verifier(ev) => {
                for _ in self.disj.clauses() {
                    accs.push(ComittedAcc::commit(
                        &mut ch,
                        dmc,
                        &self.disj,
                        &ProverPrivate::empty(ev),
                    )?);
                }
            }
        }

        // challenges for permutation proof
        let (chal_perm, chal_cmbn) = if fiat_shamir::<V>() {
            (ch.challenge(), ch.challenge())
        } else {
            match P::WHICH {
                WhichParty::Prover(_) => {
                    ch.flush()?;
                    (
                        dmc.channel.read_serializable::<V>()?,
                        dmc.channel.read_serializable::<V>()?,
                    )
                }
                WhichParty::Verifier(_) => {
                    let chal_perm = V::random(&mut dmc.rng);
                    let chal_cmbn = V::random(&mut dmc.rng);
                    dmc.channel.write_serializable(&chal_perm)?;
                    dmc.channel.write_serializable(&chal_cmbn)?;
                    dmc.channel.flush()?;
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
        permutation(dmc, chal_perm, &lhs, &rhs)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    use ocelot::svole::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};
    use scuttlebutt::{field::F61p, ring::FiniteRing, AesRng, Channel};
    use swanky_party::{Prover, Verifier, IS_VERIFIER};

    use crate::backend_trait::BackendT;
    use crate::{
        dora::{Clause, DisjGate},
        svole_trait::Svole,
        DietMacAndCheese,
    };
    use rand::{Rng, SeedableRng};

    use super::*;

    // a very simple example using a disjunction to implement a range check
    #[test]
    fn test_range_example() {
        const RANGE_SIZE: usize = 256;
        const NUM_RANGE_PROOFS: usize = 10_000;

        // a range check
        let clauses = (0..RANGE_SIZE)
            .map(|i| Clause {
                gates: vec![
                    DisjGate::AddConstant(1, 0, -F61p::try_from(i as u128).unwrap()),
                    DisjGate::AssertZero(1),
                ],
            })
            .collect::<Vec<_>>();

        let range_check = Disjunction::new(clauses.iter().cloned(), 1, 0);

        let (sender, receiver) = UnixStream::pair().unwrap();

        let range_check_clone = range_check.clone();

        let handle = std::thread::spawn(move || {
            let rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);

            let mut prover: DietMacAndCheese<Prover, F61p, F61p, _, Svole<_, _, F61p>> =
                DietMacAndCheese::init(&mut channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL, false)
                    .unwrap();

            let mut disj = Dora::<Prover, F61p, F61p, _, Svole<_, _, F61p>>::new(range_check);

            println!("warm up");
            prover.input_private(Some(F61p::ONE)).unwrap();

            // do a number of range checks
            println!("do {} range proofs", NUM_RANGE_PROOFS);
            for _ in 0..NUM_RANGE_PROOFS {
                let wi: usize = prover.rng.gen::<usize>() % RANGE_SIZE;
                let wf = F61p::try_from(wi as u128).unwrap();
                let v = prover.input_private(Some(wf)).unwrap();
                disj.mux(&mut prover, &[v], ProverPrivateCopy::new(wi))
                    .unwrap(); // because it is assigned 1
            }
            disj.finalize(&mut prover).unwrap();

            println!("finalize");
            prover.finalize().unwrap();

            println!("done");
        });

        let rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let mut dmc: DietMacAndCheese<Verifier, F61p, F61p, _, Svole<_, F61p, F61p>> =
            DietMacAndCheese::init(&mut channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL, false)
                .unwrap();

        dmc.input_private(None).unwrap();

        let mut disj = Dora::new(range_check_clone);
        for _ in 0..NUM_RANGE_PROOFS {
            let v = dmc.input_private(None).unwrap();
            disj.mux(&mut dmc, &[v], ProverPrivateCopy::empty(IS_VERIFIER))
                .unwrap();
        }
        disj.finalize(&mut dmc).unwrap();
        dmc.finalize().unwrap();

        handle.join().unwrap();
    }
}
