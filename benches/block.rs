// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(feature = "curve25519-dalek")]
use curve25519_dalek::ristretto::RistrettoPoint;
use scuttlebutt::Block;
use std::time::Duration;

#[cfg(feature = "curve25519-dalek")]
fn bench_hash_pt(c: &mut Criterion) {
    c.bench_function("Block::hash_pt", |b| {
        let pt = RistrettoPoint::random(&mut rand::thread_rng());
        let i = rand::random::<usize>();
        b.iter(|| {
            let h = Block::hash_pt(i, &pt);
            criterion::black_box(h)
        });
    });
}
#[cfg(not(feature = "curve25519-dalek"))]
fn bench_hash_pt(_c: &mut Criterion) {}

fn bench_clmul(c: &mut Criterion) {
    c.bench_function("Block::clmul", |b| {
        let x = rand::random::<Block>();
        let y = rand::random::<Block>();
        b.iter(|| {
            let z = x.clmul(y);
            criterion::black_box(z)
        });
    });
}

fn bench_xor(c: &mut Criterion) {
    c.bench_function("Block::xor", |b| {
        let x = rand::random::<Block>();
        let y = rand::random::<Block>();
        b.iter(|| {
            let z = x ^ y;
            criterion::black_box(z)
        });
    });
}

fn bench_zero(c: &mut Criterion) {
    c.bench_function("Block::zero", |b| {
        b.iter(|| {
            let z = Block::zero();
            criterion::black_box(z)
        })
    });
}

criterion_group! {
    name = block;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_hash_pt, bench_clmul, bench_xor, bench_zero
}
criterion_main!(block);
