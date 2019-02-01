use criterion::{criterion_group, criterion_main, Criterion};
use ocelot::*;

fn bench_cr_hash(c: &mut Criterion) {
    c.bench_function("cr hash", |b| {
        let hash = AesHash::new(&[0u8; 16]);
        let x = [0u8; 16];
        b.iter(|| hash.cr_hash(0, &x))
    });
}

fn bench_ccr_hash(c: &mut Criterion) {
    c.bench_function("ccr hash", |b| {
        let hash = AesHash::new(&[0u8; 16]);
        let x = [0u8; 16];
        b.iter(|| hash.ccr_hash(0, &x))
    });
}

fn bench_tranpose(c: &mut Criterion) {
    c.bench_function("transpose", |b| {
        let (nrows, ncols) = (128, 1 << 14);
        let m = vec![0u8; nrows * ncols / 8];
        b.iter(|| utils::transpose(&m, nrows, ncols))
    });
}

criterion_group! {
    name = utils;
    config = Criterion::default();
    targets = bench_cr_hash, bench_ccr_hash, bench_tranpose
}
criterion_main!(utils);
