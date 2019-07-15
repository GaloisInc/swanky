// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::RngCore;
use scuttlebutt::AesRng;
use std::time::Duration;

fn bench_aes_rand(c: &mut Criterion) {
    c.bench_function("AesRng::rand", |b| {
        let mut rng = AesRng::new();
        let mut x = (0..16 * 1024)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>();
        b.iter(|| rng.fill_bytes(&mut x));
    });
}

criterion_group! {
    name = aesrng;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_aes_rand
}
criterion_main!(aesrng);
