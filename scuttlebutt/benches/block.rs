// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(feature = "curve25519")]
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::Rng;
use scuttlebutt::{AesRng, Block};
use std::time::Duration;

#[cfg(feature = "curve25519")]
fn bench_hash_pt(c: &mut Criterion) {
    c.bench_function("Block::hash_pt", |b| {
        let pt = RistrettoPoint::random(&mut rand::thread_rng());
        let tweak = rand::random::<u128>();
        b.iter(|| {
            let h = Block::hash_pt(tweak, &pt);
            criterion::black_box(h)
        });
    });
}
#[cfg(not(feature = "curve25519"))]
fn bench_hash_pt(_: &mut Criterion) {}

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

fn bench_rand(c: &mut Criterion) {
    c.bench_function("Block::rand", |b| {
        let mut rng = AesRng::new();
        b.iter(|| {
            let block = rng.gen::<Block>();
            criterion::black_box(block)
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

fn bench_default(c: &mut Criterion) {
    c.bench_function("Block::default", |b| {
        b.iter(|| {
            let z = Block::default();
            criterion::black_box(z)
        })
    });
}

criterion_group! {
    name = block;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_hash_pt, bench_clmul, bench_rand, bench_xor, bench_default
}
criterion_main!(block);
