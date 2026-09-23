//! Benchmark code of garbling / evaluating using Nigel's circuits.

use core::time::Duration;
use criterion::{Criterion, criterion_group, criterion_main};
use fancy_circuits::crypto::{aes::Aes128, sha::Sha256CompressionFunction};
use fancy_garbling::{Garbler, WireMod2, classic::GarbledCircuit};
use fancy_traits::CircuitInputMapper;
use std::hint::black_box;
use swanky_rng::SwankyRng;

fn bench_aes_new(c: &mut Criterion) {
    c.bench_function("new::aes128", move |bench| {
        bench.iter(|| {
            let aes = Aes128::new();
            black_box(aes);
        });
    });
}

fn bench_garble_aes(c: &mut Criterion) {
    let aes = Aes128::new();
    c.bench_function("garble::aes128", move |bench| {
        bench.iter(|| GarbledCircuit::garble::<WireMod2, _, _>(&aes, SwankyRng::new()));
    });
}

fn bench_eval_aes(c: &mut Criterion) {
    let aes = Aes128::new();
    let (en, gc, _) = GarbledCircuit::garble::<WireMod2, _, _>(&aes, SwankyRng::new()).unwrap();
    let inputs = en.encode_inputs(&vec![0; 256]);
    let key = inputs[..128].try_into().unwrap();
    let block = inputs[128..].try_into().unwrap();
    c.bench_function("eval::aes128", move |bench| {
        bench.iter(|| gc.eval_to_wirelabels(&aes, (key, block)))
    });
}

fn bench_sha_256_new(c: &mut Criterion) {
    c.bench_function("new::sha256", move |bench| {
        bench.iter(|| {
            let sha = Sha256CompressionFunction::new();
            black_box(sha);
        });
    });
}

fn bench_garble_sha_256(c: &mut Criterion) {
    let sha256 = Sha256CompressionFunction::new();
    c.bench_function("garble::sha256", move |bench| {
        bench.iter(|| GarbledCircuit::garble::<WireMod2, _, _>(&sha256, SwankyRng::new()));
    });
}

fn bench_eval_sha_256(c: &mut Criterion) {
    let sha256 = Sha256CompressionFunction::new();
    let (en, gc, _) = GarbledCircuit::garble::<WireMod2, _, _>(&sha256, SwankyRng::new()).unwrap();
    let inputs = en.encode_inputs(&vec![0; 768]);
    let (block, chain) = <Sha256CompressionFunction as CircuitInputMapper<
        Garbler<SwankyRng, WireMod2>,
    >>::map(&sha256, inputs);
    c.bench_function("eval::sha256", move |bench| {
        bench.iter(|| gc.eval_to_wirelabels(&sha256, (block, chain)))
    });
}

criterion_group! {
    name = parsing;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_aes_new, bench_garble_aes, bench_eval_aes,
              bench_sha_256_new, bench_garble_sha_256, bench_eval_sha_256
}

criterion_main!(parsing);
