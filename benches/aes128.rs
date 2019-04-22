// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use criterion::{criterion_group, criterion_main, Criterion};
use scuttlebutt::{Aes128, Block};
use std::time::Duration;

fn bench_aes_new(c: &mut Criterion) {
    c.bench_function("Aes128::new", |b| {
        let key = rand::random::<Block>();
        b.iter(|| {
            let aes = Aes128::new(key);
            criterion::black_box(aes)
        });
    });
}

fn bench_aes_encrypt(c: &mut Criterion) {
    c.bench_function("Aes128::encrypt", |b| {
        let aes = Aes128::new(rand::random::<Block>());
        let block = rand::random::<Block>();
        b.iter(|| {
            let c = aes.encrypt(block);
            criterion::black_box(c)
        });
    });
}

fn bench_aes_encrypt4(c: &mut Criterion) {
    c.bench_function("Aes128::encrypt4", |b| {
        let aes = Aes128::new(rand::random::<Block>());
        let blocks = rand::random::<[Block; 4]>();
        b.iter(|| {
            let c = aes.encrypt4(blocks);
            criterion::black_box(c)
        });
    });
}

fn bench_aes_encrypt8(c: &mut Criterion) {
    c.bench_function("Aes128::encrypt8", |b| {
        let aes = Aes128::new(rand::random::<Block>());
        let blocks = rand::random::<[Block; 8]>();
        b.iter(|| {
            let c = aes.encrypt8(blocks);
            criterion::black_box(c)
        });
    });
}

criterion_group! {
    name = aes128;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_aes_new, bench_aes_encrypt, bench_aes_encrypt4, bench_aes_encrypt8
}
criterion_main!(aes128);
