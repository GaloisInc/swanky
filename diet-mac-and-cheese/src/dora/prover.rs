use eyre::Result;

use scuttlebutt::{field::FiniteField, AbstractChannel};
use swanky_field::IsSubFieldOf;
use swanky_party::{Prover, IS_PROVER};

use crate::{
    dora::{comm::CommittedWitness, tx::TxChannel, COMPACT_MIN, COMPACT_MUL},
    mac::Mac,
    svole_trait::SvoleT,
    DietMacAndCheeseProver,
};

use super::{
    acc::{self, collapse_trace, Accumulator, ComittedAcc, Trace},
    comm::CommittedCrossTerms,
    disjunction::Disjunction,
    fiat_shamir,
    perm::permutation,
};

pub struct DoraProver<
    V: IsSubFieldOf<F>,
    F: FiniteField,
    C: AbstractChannel,
    SvoleFSender: SvoleT<(V, F)>,
    SvoleFReceiver: SvoleT<F>,
> where
    F::PrimeField: IsSubFieldOf<V>,
{
    calls: usize,
    tx: blake3::Hasher,
    _ph: std::marker::PhantomData<(F, C)>,
    accs: Vec<acc::Accumulator<V>>, // current state of accumulator
    disj: Disjunction<V>,
    init: Vec<ComittedAcc<DietMacAndCheeseProver<V, F, C, SvoleFSender, SvoleFReceiver>>>,
    trace: Vec<Trace<DietMacAndCheeseProver<V, F, C, SvoleFSender, SvoleFReceiver>>>,
    max_trace: usize, // maximum trace len before compactification
}

impl<
        V: IsSubFieldOf<F>,
        F: FiniteField,
        C: AbstractChannel,
        SvoleFSender: SvoleT<(V, F)>,
        SvoleFReceiver: SvoleT<F>,
    > DoraProver<V, F, C, SvoleFSender, SvoleFReceiver>
where
    F::PrimeField: IsSubFieldOf<V>,
{
    pub fn new(disj: Disjunction<V>) -> Self {
        let accs = disj
            .clauses()
            .iter()
            .map(|rel| Accumulator::init(rel))
            .collect();
        let max_trace = std::cmp::max(disj.clauses().len() * COMPACT_MUL, COMPACT_MIN);
        Self {
            _ph: std::marker::PhantomData,
            tx: blake3::Hasher::new(),
            max_trace,
            accs,
            trace: Vec::with_capacity(max_trace),
            init: vec![],
            calls: 0,
            disj,
        }
    }

    // execute a mux over a secret clause
    //
    // returns commitments to the output
    pub fn mux(
        &mut self,
        prover: &mut DietMacAndCheeseProver<V, F, C, SvoleFSender, SvoleFReceiver>,
        input: &[Mac<Prover, V, F>],
        opt: usize,
    ) -> Result<Vec<Mac<Prover, V, F>>> {
        // check if we should compact the trace first
        if self.trace.len() >= self.max_trace {
            self.compact(prover)?;
        }

        // retrieve R1CS for active clause
        let clause = self.disj.clause(opt);

        // compute extended witness for the clause
        let wit = clause.compute_witness(input.iter().map(|inp| inp.value(IS_PROVER)));
        debug_assert!(wit.check(clause));

        // compute cross terms with accumulator
        debug_assert!(self.accs[opt].check(clause));
        let cxt = clause.cross_wit_acc(&wit, &self.accs[opt]);

        // wrap in transcript hasher (if FS enabled)
        let mut ch = TxChannel::new(prover.channel.clone(), &mut self.tx);

        // commit to extended witness
        let comm_wit = CommittedWitness::commit_prover(
            &mut ch,
            prover,
            &self.disj,
            input.iter().copied(),
            &wit,
        )?;
        debug_assert_eq!(comm_wit.value(clause), wit);

        // commit to cross terms
        let comm_cxt = CommittedCrossTerms::commit_prover(&mut ch, prover, &self.disj, &cxt)?;

        // commit to old accumulator
        let comm_acc = ComittedAcc::commit_prover(&mut ch, prover, &self.disj, &self.accs[opt])?;
        debug_assert!(self.accs[opt].check(clause));
        debug_assert_eq!(&comm_acc.value(clause), &self.accs[opt]);

        // fold extended witness, accumulator and cross terms
        let challenge = ch.challenge();
        let comm_acc_new = comm_acc.fold_witness(prover, challenge, &comm_cxt, &comm_wit)?;

        // store new accumulator
        self.accs[opt] = comm_acc_new.value(clause);
        debug_assert!(self.accs[opt].check(clause));

        // add to trace (for permutation proof)
        self.trace.push(Trace {
            old: comm_acc,
            new: comm_acc_new,
        });

        self.calls += 1;

        // returns the outputs from the extended witness
        Ok(comm_wit.outputs().to_owned())
    }

    /// Simply verify all the final accumulators using MacAndCheese
    pub fn finalize(
        mut self,
        prover: &mut DietMacAndCheeseProver<V, F, C, SvoleFSender, SvoleFReceiver>,
    ) -> Result<()>
    where
        F::PrimeField: IsSubFieldOf<V>,
    {
        log::info!(
            "finalizing Dora proof: {} calls (of dimension {}) to disjunction of {} clauses",
            self.calls,
            self.disj.dim_ext(),
            self.disj.clauses().len()
        );

        // compact trace into single set of accumulators
        self.compact(prover)?;

        // verify accumulors
        for (acc, r1cs) in self.init.into_iter().zip(self.disj.clauses()) {
            acc.verify(prover, r1cs)?;
        }
        Ok(())
    }

    // "compact" the disjunction trace (without verification)
    //
    // Commits to all the accumulators and executes the permutation proof.
    // This reduces the trace to a single element per branch.
    fn compact(
        &mut self,
        prover: &mut DietMacAndCheeseProver<V, F, C, SvoleFSender, SvoleFReceiver>,
    ) -> Result<()> {
        // commit to all accumulators
        let mut ch = TxChannel::new(prover.channel.clone(), &mut self.tx);
        let mut accs = Vec::with_capacity(self.disj.clauses().len());
        for acc in self.accs.iter() {
            accs.push(ComittedAcc::commit_prover(
                &mut ch, prover, &self.disj, acc,
            )?);
        }

        // obtain challenges for permutation proof
        let (chal_perm, chal_cmbn) = if fiat_shamir::<V>() {
            (ch.challenge(), ch.challenge())
        } else {
            ch.flush()?;
            (
                prover.channel.read_serializable::<V>()?,
                prover.channel.read_serializable::<V>()?,
            )
        };

        // combine elements from trace into single field elements
        let (mut lhs, mut rhs) = collapse_trace(prover, &self.trace, chal_cmbn)?;

        // add initial / final accumulator to permutation proof
        for (i, (acc, r1cs)) in accs.iter().zip(self.disj.clauses()).enumerate() {
            lhs.push(acc.combine(prover, chal_cmbn)?);
            rhs.push(match self.init.get(i) {
                Some(acc) => acc.combine(prover, chal_cmbn)?,
                None => Accumulator::init(r1cs).combine(prover, chal_cmbn)?,
            });
        }

        // execute permutation proof
        self.trace.clear();
        self.init = accs;
        permutation(prover, chal_perm, &lhs, &rhs)
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

    use crate::backend_trait::BackendT;
    use crate::{
        dora::{verifier::DoraVerifier, Clause, DisjGate},
        svole_trait::{SvoleReceiver, SvoleSender},
        DietMacAndCheeseVerifier,
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

            let mut prover: DietMacAndCheeseProver<
                F61p,
                F61p,
                _,
                SvoleSender<F61p>,
                SvoleReceiver<F61p, F61p>,
            > = DietMacAndCheeseProver::init(
                &mut channel,
                rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
                false,
            )
            .unwrap();

            let mut disj =
                DoraProver::<F61p, F61p, _, SvoleSender<F61p>, SvoleReceiver<F61p, F61p>>::new(
                    range_check,
                );

            println!("warm up");
            prover.input_private(Some(F61p::ONE)).unwrap();

            // do a number of range checks
            println!("do {} range proofs", NUM_RANGE_PROOFS);
            for _ in 0..NUM_RANGE_PROOFS {
                let wi: usize = prover.rng.gen::<usize>() % RANGE_SIZE;
                let wf = F61p::try_from(wi as u128).unwrap();
                let v = prover.input_private(Some(wf)).unwrap();
                disj.mux(&mut prover, &[v], wi).unwrap(); // because it is assigned 1
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

        let mut dmc: DietMacAndCheeseVerifier<
            F61p,
            F61p,
            _,
            SvoleSender<F61p>,
            SvoleReceiver<F61p, F61p>,
        > = DietMacAndCheeseVerifier::init(
            &mut channel,
            rng,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
            false,
        )
        .unwrap();

        dmc.input_private(None).unwrap();

        let mut disj = DoraVerifier::new(range_check_clone);
        for _ in 0..NUM_RANGE_PROOFS {
            let v = dmc.input_private(None).unwrap();
            disj.mux(&mut dmc, &[v]).unwrap();
        }
        disj.finalize(&mut dmc).unwrap();
        dmc.finalize().unwrap();

        handle.join().unwrap();
    }
}
