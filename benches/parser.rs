// -*- mode: rust; -*-
//
// This file is part of fancy-garbling.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

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

fn bench_garble_sha_1(c: &mut Criterion) {
    c.bench_function("garble::sha-1", move |bench| {
        let circ = Circuit::parse("circuits/sha-1.txt").unwrap();
        bench.iter(|| garble(&circ));
    });
}

fn bench_garble_sha_256(c: &mut Criterion) {
    c.bench_function("garble::sha-256", move |bench| {
        let circ = Circuit::parse("circuits/sha-256.txt").unwrap();
        bench.iter(|| garble(&circ));
    });
}

criterion_group! {
    name = parsing;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_garble_aes, bench_garble_sha_1, bench_garble_sha_256
}

criterion_main!(parsing);
