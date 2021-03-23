// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::distributions::{Distribution, Uniform};
use rand_core::RngCore;
use scuttlebutt::AesRng;

fn bench_aes_rand(c: &mut Criterion) {
    c.bench_function("AesRng::rand", |b| {
        let mut rng = AesRng::new();
        let mut x = (0..16 * 1024)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>();
        b.iter(|| rng.fill_bytes(black_box(&mut x)));
    });
}

fn bench_aes_rand_int_108000(c: &mut Criterion) {
    const BOUND: u32 = 108000;
    c.bench_function("AesRng::rand 32 integers under 108000", |b| {
        let mut rng = AesRng::new();
        let dist = Uniform::new(0, BOUND);
        b.iter(|| {
            for _ in 0..32 {
                black_box(dist.sample(&mut rng));
            }
        });
    });
    c.bench_function(
        "AesRng::uniform_integers_under_bound 32 integers under 108000",
        |b| {
            let mut rng = AesRng::new();
            b.iter(|| {
                black_box(rng.uniform_integers_under_bound::<BOUND>());
                black_box(rng.uniform_integers_under_bound::<BOUND>());
            });
        },
    );
}

fn bench_aes_rand_int_126(c: &mut Criterion) {
    const BOUND: u32 = 126;
    c.bench_function("AesRng::rand 32 integers under 126", |b| {
        let mut rng = AesRng::new();
        let dist = Uniform::new(0, BOUND);
        b.iter(|| {
            for _ in 0..32 {
                black_box(dist.sample(&mut rng));
            }
        });
    });
    c.bench_function(
        "AesRng::uniform_integers_under_bound 32 integers under 126",
        |b| {
            let mut rng = AesRng::new();
            b.iter(|| {
                black_box(rng.uniform_integers_under_bound::<BOUND>());
                black_box(rng.uniform_integers_under_bound::<BOUND>());
            });
        },
    );
}

criterion_group! {
    name = aesrng;
    config = Criterion::default();
    targets = bench_aes_rand, bench_aes_rand_int_126, bench_aes_rand_int_108000
}
criterion_main!(aesrng);
