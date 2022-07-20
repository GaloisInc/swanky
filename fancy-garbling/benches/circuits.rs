// -*- mode: rust; -*-
//
// This file is part of fancy-garbling.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Benchmark code of garbling / evaluating using Nigel's circuits.

use criterion::{criterion_group, criterion_main, Criterion};
use fancy_garbling::{circuit::Circuit, classic::garble, AllWire, WireMod2};
use std::time::Duration;

fn circuit(fname: &str) -> Circuit {
    let circ = Circuit::parse(fname).unwrap();
    // println!("{}", fname);
    // circ.print_info().unwrap();
    circ
}

fn bench_garble_aes_arith(c: &mut Criterion) {
    let circ = circuit("circuits/AES-non-expanded.txt");
    c.bench_function("garble::aes-arith", move |bench| {
        bench.iter(|| garble::<AllWire>(&circ));
    });
}

fn bench_garble_aes_binary(c: &mut Criterion) {
    let circ = circuit("circuits/AES-non-expanded.txt");
    c.bench_function("garble::aes-binary", move |bench| {
        bench.iter(|| garble::<WireMod2>(&circ));
    });
}

fn bench_eval_aes_arith(c: &mut Criterion) {
    let circ = circuit("circuits/AES-non-expanded.txt");
    let (en, gc) = garble::<AllWire>(&circ).unwrap();
    let gb = en.encode_garbler_inputs(&vec![0u16; 128]);
    let ev = en.encode_evaluator_inputs(&vec![0u16; 128]);
    c.bench_function("eval::aes-arith", move |bench| {
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

fn bench_eval_aes_binary(c: &mut Criterion) {
    let circ = circuit("circuits/AES-non-expanded.txt");
    let (en, gc) = garble::<WireMod2>(&circ).unwrap();
    let gb = en.encode_garbler_inputs(&vec![0u16; 128]);
    let ev = en.encode_evaluator_inputs(&vec![0u16; 128]);
    c.bench_function("eval::aes-binary", move |bench| {
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

fn bench_garble_sha_1_arith(c: &mut Criterion) {
    let circ = circuit("circuits/sha-1.txt");
    c.bench_function("garble::sha-1-arith", move |bench| {
        bench.iter(|| garble::<AllWire>(&circ));
    });
}

fn bench_garble_sha_1_binary(c: &mut Criterion) {
    let circ = circuit("circuits/sha-1.txt");
    c.bench_function("garble::sha-1-binary", move |bench| {
        bench.iter(|| garble::<WireMod2>(&circ));
    });
}

fn bench_eval_sha_1_arith(c: &mut Criterion) {
    let circ = circuit("circuits/sha-1.txt");
    let (en, gc) = garble::<AllWire>(&circ).unwrap();
    let gb = en.encode_garbler_inputs(&vec![0u16; 512]);
    let ev = en.encode_evaluator_inputs(&vec![]);
    c.bench_function("eval::sha-1-arith", move |bench| {
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

fn bench_eval_sha_1_binary(c: &mut Criterion) {
    let circ = circuit("circuits/sha-1.txt");
    let (en, gc) = garble::<WireMod2>(&circ).unwrap();
    let gb = en.encode_garbler_inputs(&vec![0u16; 512]);
    let ev = en.encode_evaluator_inputs(&vec![]);
    c.bench_function("eval::sha-1-binary", move |bench| {
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

fn bench_garble_sha_256_arith(c: &mut Criterion) {
    let circ = circuit("circuits/sha-256.txt");
    c.bench_function("garble::sha-256-arith", move |bench| {
        bench.iter(|| garble::<AllWire>(&circ));
    });
}
fn bench_garble_sha_256_binary(c: &mut Criterion) {
    let circ = circuit("circuits/sha-256.txt");
    c.bench_function("garble::sha-256-binary", move |bench| {
        bench.iter(|| garble::<WireMod2>(&circ));
    });
}

fn bench_eval_sha_256_arith(c: &mut Criterion) {
    let circ = circuit("circuits/sha-256.txt");
    let (en, gc) = garble::<AllWire>(&circ).unwrap();
    let gb = en.encode_garbler_inputs(&vec![0u16; 512]);
    let ev = en.encode_evaluator_inputs(&vec![]);
    c.bench_function("eval::sha-256-arith", move |bench| {
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

fn bench_eval_sha_256_binary(c: &mut Criterion) {
    let circ = circuit("circuits/sha-256.txt");
    let (en, gc) = garble::<WireMod2>(&circ).unwrap();
    let gb = en.encode_garbler_inputs(&vec![0u16; 512]);
    let ev = en.encode_evaluator_inputs(&vec![]);
    c.bench_function("eval::sha-256-binary", move |bench| {
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

criterion_group! {
    name = parsing;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_garble_aes_arith, bench_garble_aes_binary, bench_eval_aes_arith, bench_eval_aes_binary, bench_garble_sha_1_arith, bench_garble_sha_1_binary, bench_eval_sha_1_arith, bench_eval_sha_1_binary, bench_garble_sha_256_arith, bench_garble_sha_256_binary, bench_eval_sha_256_arith, bench_eval_sha_256_binary
}

criterion_main!(parsing);
