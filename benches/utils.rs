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

fn bench_aes_rand(c: &mut Criterion) {
    c.bench_function("aes rand", |b| {
        let rng = AesRng::new(&[0u8; 16]);
        let mut x = [0u8; 16 * 1024];
        b.iter(|| rng.random(&mut x));
    });
}

fn bench_receiver_start(c: &mut Criterion) {
    let (nrows, ncols) = (128, 1 << 14);
    let inputs = (0..ncols)
        .map(|_| rand::random::<bool>())
        .collect::<Vec<bool>>();
    let rng = AesRng::new(&rand::random::<Block>());
    c.bench_function("aes rand map", move |b| {
        b.iter(|| {
            let mut ks = Vec::with_capacity(nrows);
            for _ in 0..nrows {
                let mut k0 = [0u8; 16];
                let mut k1 = [0u8; 16];
                rng.random(&mut k0);
                rng.random(&mut k1);
                ks.push((k0, k1));
            }
            let rngs = ks
                .into_iter()
                .map(|(k0, k1)| (AesRng::new(&k0), AesRng::new(&k1)))
                .collect::<Vec<(AesRng, AesRng)>>();
            let r = utils::boolvec_to_u8vec(&inputs);
            let mut ts = vec![0u8; nrows * ncols / 8];
            let mut g = vec![0u8; ncols / 8];
            for (j, (rng0, rng1)) in rngs.into_iter().enumerate() {
                let range = j * ncols / 8..(j + 1) * ncols / 8;
                let mut t = &mut ts[range];
                rng0.random(&mut t);
                rng1.random(&mut g);
                utils::xor_inplace(&mut g, &t);
                utils::xor_inplace(&mut g, &r);
            }
        });
    });
}

fn bench_tranpose(c: &mut Criterion) {
    c.bench_function("transpose", |b| {
        let (nrows, ncols) = (128, 1 << 15);
        let m = vec![0u8; nrows * ncols / 8];
        b.iter(|| utils::transpose(&m, nrows, ncols))
    });
}

criterion_group! {
    name = utils;
    config = Criterion::default();
    targets = bench_cr_hash, bench_ccr_hash, bench_aes_rand, bench_receiver_start, bench_tranpose
}
criterion_main!(utils);
