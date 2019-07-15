// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use criterion::{criterion_group, criterion_main, Criterion};
use scuttlebutt::{Aes256, Block};
use std::time::Duration;

fn bench_aes_new(c: &mut Criterion) {
    c.bench_function("Aes256::new", |b| {
        let key = rand::random::<[u8; 32]>();
        b.iter(|| {
            let aes = Aes256::new(&key);
            criterion::black_box(aes)
        });
    });
}

fn bench_aes_encrypt(c: &mut Criterion) {
    c.bench_function("Aes256::encrypt", |b| {
        let aes = Aes256::new(&rand::random::<[u8; 32]>());
        let block = rand::random::<Block>();
        b.iter(|| {
            let c = aes.encrypt(block);
            criterion::black_box(c)
        });
    });
}

criterion_group! {
    name = aes256;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_aes_new, bench_aes_encrypt
}
criterion_main!(aes256);
