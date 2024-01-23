use std::{
    io::{BufReader, BufWriter},
    iter,
    os::unix::net::UnixStream,
};

use ocelot::svole::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};
use scuttlebutt::{field::F61p, ring::FiniteRing, AesRng, Channel};
use swanky_party::{private::ProverPrivateCopy, Prover, Verifier, IS_VERIFIER};

use crate::{backend_trait::BackendT, circuit_ir::WireCount};
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

        prover.input_private(Some(F61p::ONE)).unwrap();

        // do a number of range checks
        for _ in 0..NUM_RANGE_PROOFS {
            let wi: usize = prover.rng.gen::<usize>() % RANGE_SIZE;
            let wf = F61p::try_from(wi as u128).unwrap();
            let v = prover.input_private(Some(wf)).unwrap();
            disj.mux(&mut prover, iter::empty(), &[v], ProverPrivateCopy::new(wi))
                .unwrap(); // because it is assigned 1
        }
        disj.finalize(&mut prover).unwrap();

        prover.finalize().unwrap();
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
        disj.mux(
            &mut dmc,
            iter::empty(),
            &[v],
            ProverPrivateCopy::empty(IS_VERIFIER),
        )
        .unwrap();
    }
    disj.finalize(&mut dmc).unwrap();
    dmc.finalize().unwrap();

    handle.join().unwrap();
}

// a simple example of using a witness gate
#[test]
fn test_witness_example() {
    const INPUTS: usize = 256;
    const OUTPUTS: usize = 1;

    const FREE: usize = INPUTS + OUTPUTS;

    const OUTPUT: usize = 0;
    const INPUT: usize = 1;

    fn nth_input(n: usize) -> usize {
        INPUT + n
    }

    // compute inverse of the first n inputs and add the inverses
    // note: this means different numbers of witness gates are used in each clause
    let clauses = (0..256)
        .map(|i| {
            let mut gates = Vec::new();
            let mut nxt = FREE;
            for n in 0..i {
                let w_inv = nxt;
                let w_mul = nxt + 1;
                let w_val = nth_input(n);
                nxt += 2;

                // add inverse
                gates.append(&mut vec![
                    DisjGate::Witness(w_inv),             // wit inverse
                    DisjGate::Add(OUTPUT, OUTPUT, w_inv), // add to output
                    DisjGate::Mul(w_mul, w_inv, w_val),   // compute witness inverse * witness value
                    DisjGate::AssertConstant(w_mul, F61p::ONE),
                ]);
            }

            Clause { gates }
        })
        .collect::<Vec<_>>();

    let disj = Disjunction::new(
        clauses.iter().cloned(),
        INPUTS as WireCount,
        OUTPUTS as WireCount,
    );

    let (sender, receiver) = UnixStream::pair().unwrap();

    let range_check_clone = disj.clone();

    let handle = std::thread::spawn(move || {
        let rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(sender.try_clone().unwrap());
        let writer = BufWriter::new(sender);
        let mut channel = Channel::new(reader, writer);

        let mut prover: DietMacAndCheese<Prover, F61p, F61p, _, Svole<_, _, F61p>> =
            DietMacAndCheese::init(&mut channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL, false)
                .unwrap();

        let mut disj = Dora::<Prover, F61p, F61p, _, Svole<_, _, F61p>>::new(disj);

        // select clause
        let wi = prover.rng.gen::<usize>() % 256;

        // generate input and witness
        let mut wit_tape: Vec<F61p> = Vec::new();
        let mut input = Vec::new();

        for n in 0..INPUTS {
            let v = prover.rng.gen::<F61p>();
            let vin = if n < wi {
                v.inverse()
            } else {
                0.try_into().unwrap() // pad with zeros
            };
            wit_tape.push(vin);
            input.push(prover.input_private(Some(v)).unwrap());
        }

        // do a number of range checks

        disj.mux(
            &mut prover,
            wit_tape.into_iter(),
            &input,
            ProverPrivateCopy::new(wi),
        )
        .unwrap();
        disj.finalize(&mut prover).unwrap();
        prover.finalize().unwrap();
    });

    let rng = AesRng::from_seed(Default::default());
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);

    let mut verifier: DietMacAndCheese<Verifier, F61p, F61p, _, Svole<_, F61p, F61p>> =
        DietMacAndCheese::init(&mut channel, rng, LPN_SETUP_SMALL, LPN_EXTEND_SMALL, false)
            .unwrap();

    let mut input = Vec::new();

    for _ in 0..INPUTS {
        input.push(verifier.input_private(None).unwrap());
    }

    let mut disj = Dora::new(range_check_clone);

    disj.mux(
        &mut verifier,
        iter::empty(),
        &input,
        ProverPrivateCopy::empty(IS_VERIFIER),
    )
    .unwrap();

    disj.finalize(&mut verifier).unwrap();
    verifier.finalize().unwrap();

    handle.join().unwrap();
}
