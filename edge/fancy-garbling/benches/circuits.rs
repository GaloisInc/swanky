//! Benchmark code of garbling / evaluating using Nigel's circuits.

use core::time::Duration;
use criterion::{Criterion, criterion_group, criterion_main};
use fancy_circuits::crypto::{aes::Aes128, sha::Sha256CompressionFunctionFixedIV};
use fancy_garbling::{WireMod2, classic::GarbledCircuit};
use std::hint::black_box;
use swanky_rng::SwankyRng;

fn bench_aes_new(c: &mut Criterion) {
    c.bench_function("new::aes", move |bench| {
        bench.iter(|| {
            let aes = Aes128::new();
            black_box(aes);
        });
    });
}

fn bench_garble_aes_binary(c: &mut Criterion) {
    let aes = Aes128::new();
    c.bench_function("garble::aes-binary", move |bench| {
        bench.iter(|| GarbledCircuit::garble::<WireMod2, _, _>(&aes, SwankyRng::new()));
    });
}

fn bench_eval_aes_binary(c: &mut Criterion) {
    let aes = Aes128::new();
    let (en, gc, _) = GarbledCircuit::garble::<WireMod2, _, _>(&aes, SwankyRng::new()).unwrap();
    let inputs = en.encode_inputs(&vec![0; 256]);
    let key = inputs[..128].try_into().unwrap();
    let block = inputs[128..].try_into().unwrap();
    c.bench_function("eval::aes-binary", move |bench| {
        bench.iter(|| gc.eval_to_wirelabels(&aes, (key, block)))
    });
}

fn bench_garble_sha_256_binary(c: &mut Criterion) {
    let sha256 = Sha256CompressionFunctionFixedIV::new();
    c.bench_function("garble::sha-256-binary", move |bench| {
        bench.iter(|| GarbledCircuit::garble::<WireMod2, _, _>(&sha256, SwankyRng::new()));
    });
}

fn bench_eval_sha_256_binary(c: &mut Criterion) {
    let sha256 = Sha256CompressionFunctionFixedIV::new();
    let (en, gc, _) = GarbledCircuit::garble::<WireMod2, _, _>(&sha256, SwankyRng::new()).unwrap();
    let inputs = en.encode_inputs(&vec![0; 512]);
    let block = inputs.try_into().unwrap();
    c.bench_function("eval::sha-256-binary", move |bench| {
        bench.iter(|| gc.eval_to_wirelabels(&sha256, block))
    });
}

criterion_group! {
    name = parsing;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_aes_new, bench_garble_aes_binary, bench_eval_aes_binary,
              bench_garble_sha_256_binary, bench_eval_sha_256_binary
}

criterion_main!(parsing);
