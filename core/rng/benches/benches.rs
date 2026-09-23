use criterion::{Criterion, criterion_group, criterion_main};
use rand::{
    Rng, RngExt,
    distr::{Distribution, Uniform},
};
use std::hint::black_box;
use swanky_rng::{Aes128Rng, UniformIntegersUnderBound};
use vectoreyes::U8x16;

mod measurement {
    use criterion::measurement::WallTime;
    pub(super) type Measurement = WallTime;

    pub(super) fn new_measurement() -> Measurement {
        WallTime
    }
}

use measurement::*;

fn bench_aes_rand_random(c: &mut Criterion<Measurement>) {
    c.bench_function("Aes128Rng::random::<[u8; 16]>", |b| {
        let mut rng = Aes128Rng::new();
        b.iter(|| {
            let result = rng.random::<[u8; 16]>();
            black_box(result);
        });
    });

    c.bench_function("Aes128Rng::random::<u64>", |b| {
        let mut rng = Aes128Rng::new();
        b.iter(|| {
            let result = rng.random::<u64>();
            black_box(result);
        });
    });

    c.bench_function("Aes128Rng::random::<u128>", |b| {
        let mut rng = Aes128Rng::new();
        b.iter(|| {
            let result = rng.random::<u128>();
            black_box(result);
        });
    });

    c.bench_function("Aes128Rng::random::<U8x16>", |b| {
        let mut rng = Aes128Rng::new();
        b.iter(|| {
            let result = rng.random::<U8x16>();
            black_box(result);
        });
    });
}

fn bench_aes_rand_fill_bytes(c: &mut Criterion<Measurement>) {
    c.bench_function("Aes128Rng::fill_bytes ([u8; 16])", |b| {
        let mut rng = Aes128Rng::new();
        let mut bytes = [0u8; 16];
        b.iter(|| {
            rng.fill_bytes(&mut bytes);
            black_box(bytes);
        });
    });

    c.bench_function("Aes128Rng::fill_bytes (u64)", |b| {
        let mut rng = Aes128Rng::new();
        let mut bytes = [0u8; 8];
        b.iter(|| {
            rng.fill_bytes(&mut bytes);
            black_box(bytes);
        });
    });
}

fn bench_aes_rand_int_108000(c: &mut Criterion<Measurement>) {
    const BOUND: u32 = 108000;
    c.bench_function("Aes128Rng::rand 32 integers under 108000", |b| {
        let mut rng = Aes128Rng::new();
        let dist = Uniform::new(0, BOUND).expect("bounds finite and low < high");
        b.iter(|| {
            for _ in 0..32 {
                black_box(dist.sample(&mut rng));
            }
        });
    });
    c.bench_function(
        "Aes128Rng::uniform_integers_under_bound 32 integers under 108000",
        |b| {
            let mut rng = Aes128Rng::new();
            let dist = UniformIntegersUnderBound::new(BOUND);
            b.iter(|| {
                black_box(dist.sample(&mut rng));
                black_box(dist.sample(&mut rng));
            });
        },
    );
}

fn bench_aes_rand_int_126(c: &mut Criterion<Measurement>) {
    const BOUND: u32 = 126;
    c.bench_function("Aes128Rng::rand 32 integers under 126", |b| {
        let mut rng = Aes128Rng::new();
        let dist = Uniform::new(0, BOUND).expect("bounds finite and low < high");
        b.iter(|| {
            for _ in 0..32 {
                black_box(dist.sample(&mut rng));
            }
        });
    });
    c.bench_function(
        "Aes128Rng::uniform_integers_under_bound 32 integers under 126",
        |b| {
            let mut rng = Aes128Rng::new();
            let dist = UniformIntegersUnderBound::new(BOUND);
            b.iter(|| {
                black_box(dist.sample(&mut rng));
                black_box(dist.sample(&mut rng));
            });
        },
    );
}

criterion_group! {
    name = aes_rng;
    config = Criterion::default().with_measurement(new_measurement()).sample_size(4096);
    targets = bench_aes_rand_random,
              bench_aes_rand_fill_bytes,
              bench_aes_rand_int_126,
              bench_aes_rand_int_108000
}
criterion_main!(aes_rng);
