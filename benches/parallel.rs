#![allow(non_snake_case)]

use criterion::{criterion_main, criterion_group, Criterion};
use itertools::Itertools;
use rand;

use fancy_garbling::{Fancy, BundleGadgets, HasModulus, Garbler, Evaluator, Message};
use fancy_garbling::util::{self, RngExt};

fn parallel_gadget<F,W>(b: &F, Q: u128, N: u8, par: bool)
    where W: Clone + HasModulus + Send + Sync + std::fmt::Debug,
        F: Fancy<Item=W> + Send + Sync,
    {
    let inps = b.garbler_input_bundles_crt(None, Q, N as usize);
    if par {
        crossbeam::scope(|scope| {
            b.begin_sync(N);
            let hs = inps.iter().enumerate().map(|(i,inp)| {
                scope.spawn(move |_| {
                    let z = b.exact_relu(Some(i as u8), inp);
                    let z = b.exact_relu(Some(i as u8), &z);
                    let z = b.exact_relu(Some(i as u8), &z);
                    let z = b.exact_relu(Some(i as u8), &z);
                    let z = b.exact_relu(Some(i as u8), &z);
                    let z = b.exact_relu(Some(i as u8), &z);
                    b.finish_index(i as u8);
                    z
                })
            }).collect_vec();
            let outs = hs.into_iter().map(|h| h.join().expect("join fail")).collect_vec();
            b.output_bundles(None, &outs);
        }).expect("scoped thread fail");
    } else {
        for inp in inps.iter() {
            let z = b.exact_relu(None, inp);
            let z = b.exact_relu(None, &z);
            let z = b.exact_relu(None, &z);
            let z = b.exact_relu(None, &z);
            let z = b.exact_relu(None, &z);
            let z = b.exact_relu(None, &z);
            b.output_bundle(None, &z)
        }
    }
}

fn bench_setup(c: &mut Criterion, par: bool) {
    c.bench_function(if par { "parallel streaming" } else { "sequential streaming" }, move |b| {
        let mut rng = rand::thread_rng();
        let N = 20;
        let Q = util::modulus_with_width(10);

        b.iter(|| {
            let input = (0..N).flat_map(|_| util::crt_factor(rng.gen_u128() % Q, Q)).collect_vec();

            let (tx, rx) = std::sync::mpsc::channel();

            let mut input_iter = input.into_iter();
            let gb_tx = tx.clone();
            let send_func = move |ix,m| {
                let m = match m {
                    Message::UnencodedGarblerInput { zero, delta } => {
                        let x = input_iter.next().expect("input iter fail");
                        let w = zero.plus(&delta.cmul(x));
                        Message::GarblerInput(w)
                    }
                    _ => m,
                };
                gb_tx.send((ix,m)).expect("garbler channel fail");
            };

            // put garbler on another thread
            std::thread::spawn(move || {
                let garbler = Garbler::new(send_func);
                parallel_gadget(&garbler, Q, N, par);
            });

            // run the evaluator on this one
            let evaluator = Evaluator::new(move || rx.recv().expect("evaluator channel fail"));
            parallel_gadget(&evaluator, Q, N, par);
        });
    });
}

fn bench_parallel(c: &mut Criterion) {
    bench_setup(c, true);
}

fn bench_sequential(c: &mut Criterion) {
    bench_setup(c, false);
}

criterion_group!(parallel, bench_parallel, bench_sequential);
criterion_main!(parallel);
