// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;
use scuttlebutt::{AesRng, Block512};
use std::time::Duration;

fn bench_rand(c: &mut Criterion) {
    c.bench_function("Block512::rand", |b| {
        let mut rng = AesRng::new();
        b.iter(|| {
            let block = rng.gen::<Block512>();
            criterion::black_box(block)
        });
    });
}

fn bench_xor(c: &mut Criterion) {
    c.bench_function("Block512::xor", |b| {
        let x = rand::random::<Block512>();
        let y = rand::random::<Block512>();
        b.iter(|| {
            let z = x ^ y;
            criterion::black_box(z)
        });
    });
}

fn bench_default(c: &mut Criterion) {
    c.bench_function("Block512::default", |b| {
        b.iter(|| {
            let z = Block512::default();
            criterion::black_box(z)
        })
    });
}

criterion_group! {
    name = block512;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_rand, bench_xor, bench_default
}
criterion_main!(block512);
