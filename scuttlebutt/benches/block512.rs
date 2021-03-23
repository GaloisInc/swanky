// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::Rng;
use scuttlebutt::{AesRng, Block512};

fn bench_rand(c: &mut Criterion) {
    c.bench_function("Block512::rand", |b| {
        let mut rng = AesRng::new();
        b.iter(|| {
            let block = rng.gen::<Block512>();
            black_box(block)
        });
    });
}

criterion_group! {
    name = block512;
    config = Criterion::default();
    targets = bench_rand
}
criterion_main!(block512);
