// -*- mode: rust; -*-
//
// This file is part of fancy-garbling.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Benchmark code of garbling / evaluating using Nigel's circuits.

use criterion::{criterion_group, criterion_main, Criterion};
use fancy_garbling::{circuit::Circuit, classic::garble};
use std::time::Duration;

fn circuit(fname: &str) -> Circuit {
    let circ = Circuit::parse(fname).unwrap();
    // println!("{}", fname);
    // circ.print_info().unwrap();
    circ
}

fn bench_garble_aes(c: &mut Criterion) {
    let circ = circuit("circuits/AES-non-expanded.txt");
    c.bench_function("garble::aes", move |bench| {
        bench.iter(|| garble(&circ));
    });
}

fn bench_eval_aes(c: &mut Criterion) {
    let circ = circuit("circuits/AES-non-expanded.txt");
    let (en, gc) = garble(&circ).unwrap();
    let gb = en.encode_garbler_inputs(&vec![0u16; 128]);
    let ev = en.encode_evaluator_inputs(&vec![0u16; 128]);
    c.bench_function("eval::aes", move |bench| {
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

fn bench_garble_sha_1(c: &mut Criterion) {
    let circ = circuit("circuits/sha-1.txt");
    c.bench_function("garble::sha-1", move |bench| {
        bench.iter(|| garble(&circ));
    });
}

fn bench_eval_sha_1(c: &mut Criterion) {
    let circ = circuit("circuits/sha-1.txt");
    let (en, gc) = garble(&circ).unwrap();
    let gb = en.encode_garbler_inputs(&vec![0u16; 512]);
    let ev = en.encode_evaluator_inputs(&vec![]);
    c.bench_function("eval::sha-1", move |bench| {
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

fn bench_garble_sha_256(c: &mut Criterion) {
    let circ = circuit("circuits/sha-256.txt");
    c.bench_function("garble::sha-256", move |bench| {
        bench.iter(|| garble(&circ));
    });
}

fn bench_eval_sha_256(c: &mut Criterion) {
    let circ = circuit("circuits/sha-256.txt");
    let (en, gc) = garble(&circ).unwrap();
    let gb = en.encode_garbler_inputs(&vec![0u16; 512]);
    let ev = en.encode_evaluator_inputs(&vec![]);
    c.bench_function("eval::sha-256", move |bench| {
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

criterion_group! {
    name = parsing;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_garble_aes, bench_eval_aes, bench_garble_sha_1, bench_eval_sha_1, bench_garble_sha_256, bench_eval_sha_256
}

criterion_main!(parsing);
