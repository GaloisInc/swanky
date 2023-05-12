//! Benchmark code of garbling / evaluating using Nigel's circuits.

use criterion::{criterion_group, criterion_main, Criterion};
use fancy_garbling::{circuit::BinaryCircuit, classic::garble, AllWire, WireMod2};
use std::{fs::File, io::BufReader, time::Duration};

fn circuit(fname: &str) -> BinaryCircuit {
    // println!("{}", fname);
    // circ.print_info().unwrap();
    BinaryCircuit::parse(BufReader::new(File::open(fname).unwrap())).unwrap()
}
fn bench_garble_aes_binary(c: &mut Criterion) {
    let circ = circuit("circuits/AES-non-expanded.txt");
    c.bench_function("garble::aes-binary", move |bench| {
        bench.iter(|| garble::<WireMod2, _>(&circ));
    });
}

fn bench_eval_aes_binary(c: &mut Criterion) {
    let circ = circuit("circuits/AES-non-expanded.txt");
    let (en, gc) = garble::<WireMod2, _>(&circ).unwrap();
    let gb = en.encode_garbler_inputs(&vec![0u16; 128]);
    let ev = en.encode_evaluator_inputs(&vec![0u16; 128]);
    c.bench_function("eval::aes-binary", move |bench| {
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

fn bench_garble_sha_1_binary(c: &mut Criterion) {
    let circ = circuit("circuits/sha-1.txt");
    c.bench_function("garble::sha-1-binary", move |bench| {
        bench.iter(|| garble::<WireMod2, _>(&circ));
    });
}

fn bench_eval_sha_1_binary(c: &mut Criterion) {
    let circ = circuit("circuits/sha-1.txt");
    let (en, gc) = garble::<WireMod2, _>(&circ).unwrap();
    let gb = en.encode_garbler_inputs(&vec![0u16; 512]);
    let ev = en.encode_evaluator_inputs(&[]);
    c.bench_function("eval::sha-1-binary", move |bench| {
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

fn bench_garble_sha_256_binary(c: &mut Criterion) {
    let circ = circuit("circuits/sha-256.txt");
    c.bench_function("garble::sha-256-binary", move |bench| {
        bench.iter(|| garble::<WireMod2, _>(&circ));
    });
}

fn bench_eval_sha_256_binary(c: &mut Criterion) {
    let circ = circuit("circuits/sha-256.txt");
    let (en, gc) = garble::<WireMod2, _>(&circ).unwrap();
    let gb = en.encode_garbler_inputs(&vec![0u16; 512]);
    let ev = en.encode_evaluator_inputs(&[]);
    c.bench_function("eval::sha-256-binary", move |bench| {
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

fn bench_garble_aes_arithmetic(c: &mut Criterion) {
    let circ = circuit("circuits/AES-non-expanded.txt");
    c.bench_function("garble::aes-arithmetic", move |bench| {
        bench.iter(|| garble::<AllWire, _>(&circ));
    });
}

fn bench_eval_aes_arithmetic(c: &mut Criterion) {
    let circ = circuit("circuits/AES-non-expanded.txt");
    let (en, gc) = garble::<AllWire, _>(&circ).unwrap();
    let gb = en.encode_garbler_inputs(&vec![0u16; 128]);
    let ev = en.encode_evaluator_inputs(&vec![0u16; 128]);
    c.bench_function("eval::aes-arithmetic", move |bench| {
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

fn bench_garble_sha_1_arithmetic(c: &mut Criterion) {
    let circ = circuit("circuits/sha-1.txt");
    c.bench_function("garble::sha-1-arithmetic", move |bench| {
        bench.iter(|| garble::<AllWire, _>(&circ));
    });
}

fn bench_eval_sha_1_arithmetic(c: &mut Criterion) {
    let circ = circuit("circuits/sha-1.txt");
    let (en, gc) = garble::<AllWire, _>(&circ).unwrap();
    let gb = en.encode_garbler_inputs(&vec![0u16; 512]);
    let ev = en.encode_evaluator_inputs(&[]);
    c.bench_function("eval::sha-1-arithmetic", move |bench| {
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

fn bench_garble_sha_256_arithmetic(c: &mut Criterion) {
    let circ = circuit("circuits/sha-256.txt");
    c.bench_function("garble::sha-256-arithmetic", move |bench| {
        bench.iter(|| garble::<AllWire, _>(&circ));
    });
}

fn bench_eval_sha_256_arithmetic(c: &mut Criterion) {
    let circ = circuit("circuits/sha-256.txt");
    let (en, gc) = garble::<AllWire, _>(&circ).unwrap();
    let gb = en.encode_garbler_inputs(&vec![0u16; 512]);
    let ev = en.encode_evaluator_inputs(&[]);
    c.bench_function("eval::sha-256-arithmetic", move |bench| {
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

criterion_group! {
    name = parsing;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_garble_aes_binary, bench_garble_aes_arithmetic, bench_eval_aes_binary, bench_eval_aes_arithmetic,  bench_garble_sha_1_binary,  bench_garble_sha_1_arithmetic,
    bench_eval_sha_1_binary, bench_eval_sha_1_arithmetic,  bench_garble_sha_256_binary, bench_garble_sha_256_arithmetic,  bench_eval_sha_256_binary, bench_eval_sha_256_arithmetic


}

criterion_main!(parsing);
