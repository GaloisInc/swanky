// -*- mode: rust; -*-
//
// This file is part of fancy-garbling.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Benchmark code of garbling / evaluating using Nigel's circuits.

use criterion::{criterion_group, criterion_main, Criterion};
use fancy_garbling::circuit::Circuit;
use fancy_garbling::garble;
use std::time::Duration;

fn bench_garble_aes(c: &mut Criterion) {
    c.bench_function("garble::aes", move |bench| {
        let circ = Circuit::parse("circuits/AES-non-expanded.txt").unwrap();
        bench.iter(|| garble(&circ));
    });
}

fn bench_eval_aes(c: &mut Criterion) {
    c.bench_function("eval::aes", move |bench| {
        let circ = Circuit::parse("circuits/AES-non-expanded.txt").unwrap();
        let (en, _, gc) = garble(&circ).unwrap();
        let gb = en.encode_garbler_inputs(&vec![0u16; 128]);
        let ev = en.encode_evaluator_inputs(&vec![0u16; 128]);
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

fn bench_garble_sha_1(c: &mut Criterion) {
    c.bench_function("garble::sha-1", move |bench| {
        let circ = Circuit::parse("circuits/sha-1.txt").unwrap();
        bench.iter(|| garble(&circ));
    });
}

fn bench_eval_sha_1(c: &mut Criterion) {
    c.bench_function("eval::sha-1", move |bench| {
        let circ = Circuit::parse("circuits/sha-1.txt").unwrap();
        let (en, _, gc) = garble(&circ).unwrap();
        let gb = en.encode_garbler_inputs(&vec![0u16; 512]);
        let ev = en.encode_evaluator_inputs(&vec![]);
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

fn bench_garble_sha_256(c: &mut Criterion) {
    c.bench_function("garble::sha-256", move |bench| {
        let circ = Circuit::parse("circuits/sha-256.txt").unwrap();
        bench.iter(|| garble(&circ));
    });
}

fn bench_eval_sha_256(c: &mut Criterion) {
    c.bench_function("eval::sha-256", move |bench| {
        let circ = Circuit::parse("circuits/sha-256.txt").unwrap();
        let (en, _, gc) = garble(&circ).unwrap();
        let gb = en.encode_garbler_inputs(&vec![0u16; 512]);
        let ev = en.encode_evaluator_inputs(&vec![]);
        bench.iter(|| gc.eval(&circ, &gb, &ev));
    });
}

criterion_group! {
    name = parsing;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_garble_aes, bench_eval_aes, bench_garble_sha_1, bench_eval_sha_1, bench_garble_sha_256, bench_eval_sha_256
}

criterion_main!(parsing);
