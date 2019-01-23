#![allow(non_snake_case)]

use fancy_garbling::fancy::{Fancy, BundleGadgets, HasModulus};
use fancy_garbling::garble::{Garbler, Evaluator, Message};
use fancy_garbling::util::{RngExt, modulus_with_width, crt_factor};
use itertools::Itertools;
use rand::thread_rng;

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
        }).unwrap();
    } else {
        for inp in inps.iter() {
            let y = b.exact_relu(None, inp);
            b.output_bundle(None, &y)
        }
    }
}

fn main() {
    let parallel = true;

    let mut rng = thread_rng();
    let N = 10;
    let Q = modulus_with_width(4);

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
        parallel_gadget(&garbler, Q, N, parallel);
    });

    // run the evaluator on this one
    let evaluator = Evaluator::new(move |_| rx.recv().unwrap());
    parallel_gadget(&evaluator, Q, N, parallel);
}
