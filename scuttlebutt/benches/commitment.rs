// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use criterion::{criterion_group, criterion_main, Criterion};
use scuttlebutt::commitment::{Commitment, ShaCommitment};
use std::time::Duration;

fn bench_sha_commitment(c: &mut Criterion) {
    c.bench_function("ShaCommitment::new", |b| {
        let seed = rand::random::<[u8; 32]>();
        b.iter(|| {
            let c = ShaCommitment::new(seed);
            criterion::black_box(c)
        });
    });

    c.bench_function("ShaCommitment::commit", |b| {
        let seed = rand::random::<[u8; 32]>();
        let input = rand::random::<[u8; 32]>();
        b.iter(|| {
            let mut commit = ShaCommitment::new(seed);
            commit.input(&input);
            let c = commit.finish();
            criterion::black_box(c)
        });
    });
}

criterion_group! {
    name = commitment;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_sha_commitment
}
criterion_main!(commitment);
