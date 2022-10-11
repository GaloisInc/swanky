use criterion::{black_box, criterion_group, criterion_main, Criterion};
use scuttlebutt::commitment::{Commitment, ShaCommitment};

fn bench_sha_commitment(c: &mut Criterion) {
    c.bench_function("ShaCommitment::new", |b| {
        let seed = rand::random::<[u8; 32]>();
        b.iter(|| {
            let c = ShaCommitment::new(black_box(seed));
            black_box(c)
        });
    });

    c.bench_function("ShaCommitment::commit", |b| {
        let seed = rand::random::<[u8; 32]>();
        let input = rand::random::<[u8; 32]>();
        b.iter(|| {
            let mut commit = ShaCommitment::new(black_box(seed));
            commit.input(black_box(&input));
            let c = commit.finish();
            black_box(c)
        });
    });
}

criterion_group! {
    name = commitment;
    config = Criterion::default();
    targets = bench_sha_commitment
}
criterion_main!(commitment);
