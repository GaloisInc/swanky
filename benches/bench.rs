use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(feature = "curve25519-dalek")]
use curve25519_dalek::ristretto::RistrettoPoint;
use rand_core::RngCore;
use scuttlebutt::*;

fn bench_cr_hash(c: &mut Criterion) {
    c.bench_function("cr hash", |b| {
        let hash = AesHash::new(rand::random::<Block>());
        let x = rand::random::<Block>();
        let i = rand::random::<usize>();
        b.iter(|| hash.cr_hash(i, x));
    });
}

fn bench_ccr_hash(c: &mut Criterion) {
    c.bench_function("ccr hash", |b| {
        let hash = AesHash::new(rand::random::<Block>());
        let x = rand::random::<Block>();
        let i = rand::random::<usize>();
        b.iter(|| hash.ccr_hash(i, x));
    });
}

fn bench_tccr_hash(c: &mut Criterion) {
    c.bench_function("tccr hash", |b| {
        let hash = AesHash::new(rand::random::<Block>());
        let x = rand::random::<Block>();
        let i = rand::random::<usize>();
        b.iter(|| hash.tccr_hash(i, x));
    });
}

fn bench_aes_rand(c: &mut Criterion) {
    c.bench_function("aes rand", |b| {
        let mut rng = AesRng::new();
        let mut x = (0..16 * 1024)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>();
        b.iter(|| rng.fill_bytes(&mut x));
    });
}

fn bench_hash_pt(c: &mut Criterion) {
    #[cfg(feature = "curve25519-dalek")]
    c.bench_function("hash pt", |b| {
        let pt = RistrettoPoint::random(&mut rand::thread_rng());
        let i = rand::random::<usize>();
        b.iter(|| Block::hash_pt(i, &pt));
    });
}

fn bench_xor(c: &mut Criterion) {
    c.bench_function("xor", |b| {
        let x = rand::random::<Block>();
        let y = rand::random::<Block>();
        b.iter(|| x ^ y);
    });
}

fn bench_mul128(c: &mut Criterion) {
    c.bench_function("mul128", |b| {
        let x = rand::random::<Block>();
        let y = rand::random::<Block>();
        b.iter(|| x.mul128(y));
    });
}

criterion_group! {
    name = bench;
    config = Criterion::default();
    targets = bench_cr_hash, bench_ccr_hash, bench_tccr_hash, bench_aes_rand, bench_hash_pt, bench_xor, bench_mul128
}
criterion_main!(bench);
