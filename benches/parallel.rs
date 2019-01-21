#![allow(non_snake_case)]

use criterion::{criterion_main, criterion_group, Criterion};
use fancy_garbling::fancy::{Fancy, BundleGadgets, HasModulus};
use fancy_garbling::garble::{Garbler, Evaluator, Message};
use fancy_garbling::util::{RngExt, modulus_with_width, crt_factor};
use itertools::Itertools;
use rand::thread_rng;
use std::time::Duration;

fn parallel_gadget<F,W>(b: &F, Q: u128, N: usize, par: bool)
    where W: Clone + Default + HasModulus + Send + Sync + std::fmt::Debug,
        F: Fancy<Item=W> + Send + Sync,
    {
    let inps = b.garbler_input_bundles_crt(None, Q, N);

    if par {
        crossbeam::scope(|scope| {
            b.begin_sync(0,N);
            let hs = inps.iter().enumerate().map(|(i,inp)| {
                scope.spawn(move |_| {
                    let z = b.exact_relu(Some(i), inp);
                    b.finish_index(i);
                    z
                })
            }).collect_vec();
            let outs = hs.into_iter().map(|h| h.join().unwrap()).collect_vec();
            b.output_bundles(None, &outs);
        }).unwrap()

    } else {
        b.begin_sync(0,N);
        let outs = inps.iter().enumerate().map(|(i,inp)| {
            let z = b.exact_relu(Some(i), inp);
            b.finish_index(i);
            z
        }).collect_vec();
        b.output_bundles(None, &outs);
    }
}

fn bench_parallel(c: &mut Criterion) {
    c.bench_function("parallel streaming", |b| {
        let mut rng = thread_rng();
        let N = 20;
        let Q = modulus_with_width(10);

        b.iter(|| {
            let input = (0..N).flat_map(|_| crt_factor(rng.gen_u128() % Q, Q)).collect_vec();

            let (tx, rx) = std::sync::mpsc::channel();

            let mut input_iter = input.into_iter();
            let send_func = move |m| {
                let m = match m {
                    Message::UnencodedGarblerInput { zero, delta } => {
                        let x = input_iter.next().unwrap();
                        let w = zero.plus(&delta.cmul(x));
                        Message::GarblerInput(w)
                    }
                    _ => m,
                };
                tx.send(m).unwrap();
            };

            // put garbler on another thread
            std::thread::spawn(move || {
                let garbler = Garbler::new(send_func);
                parallel_gadget(&garbler, Q, N, true);
            });

            // run the evaluator on this one
            let evaluator = Evaluator::new(move |_| rx.recv().unwrap());
            parallel_gadget(&evaluator, Q, N, false);
        });
    });
}

criterion_group!{
    name = parallel;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_parallel,
}

criterion_main!(parallel);
