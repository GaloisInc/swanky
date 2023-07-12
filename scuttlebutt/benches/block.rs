use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::Rng;
use scuttlebutt::{AesRng, Block};

fn bench_hash_pt(c: &mut Criterion) {
    c.bench_function("Block::hash_pt", |b| {
        let pt = RistrettoPoint::random(&mut rand::thread_rng());
        let tweak = rand::random::<u128>();
        b.iter(|| {
            let h = Block::hash_pt(black_box(tweak), black_box(&pt));
            black_box(h)
        });
    });
}

fn bench_clmul(c: &mut Criterion) {
    c.bench_function("Block::clmul", |b| {
        let x = rand::random::<Block>();
        let y = rand::random::<Block>();
        b.iter(|| {
            let z = x.clmul(black_box(y));
            black_box(z)
        });
    });
}

fn bench_rand(c: &mut Criterion) {
    c.bench_function("Block::rand", |b| {
        let mut rng = AesRng::new();
        b.iter(|| {
            let block = rng.gen::<Block>();
            black_box(block)
        });
    });
}

fn bench_xor(c: &mut Criterion) {
    c.bench_function("Block::xor", |b| {
        let x = rand::random::<Block>();
        let y = rand::random::<Block>();
        b.iter(|| {
            let z = black_box(x) ^ black_box(y);
            black_box(z)
        });
    });
}

fn bench_default(c: &mut Criterion) {
    c.bench_function("Block::default", |b| {
        b.iter(|| {
            let z = black_box(Block::default());
            black_box(z)
        })
    });
}

criterion_group! {
    name = block;
    config = Criterion::default();
    targets = bench_hash_pt, bench_clmul, bench_rand, bench_xor, bench_default
}
criterion_main!(block);
