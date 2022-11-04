use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::distributions::{Distribution, Uniform};
use rand_core::RngCore;
use scuttlebutt::{AesRng, UniformIntegersUnderBound};

mod measurement {
    use criterion::measurement::WallTime;
    pub(super) type Measurement = WallTime;

    pub(super) fn new_measurement() -> Measurement {
        WallTime
    }
}

use measurement::*;

fn bench_aes_rand(c: &mut Criterion<Measurement>) {
    c.bench_function("AesRng::rand", |b| {
        let mut rng = AesRng::new();
        let mut x = (0..16 * 1024)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>();
        b.iter(|| rng.fill_bytes(black_box(&mut x)));
    });
}

fn bench_aes_rand_int_108000(c: &mut Criterion<Measurement>) {
    const BOUND: u32 = 108000;
    c.bench_function("AesRng::rand 32 integers under 108000", |b| {
        let mut rng = AesRng::new();
        let dist = Uniform::new(0, BOUND);
        b.iter(|| {
            for _ in 0..32 {
                black_box(dist.sample(&mut rng));
            }
        });
    });
    c.bench_function(
        "AesRng::uniform_integers_under_bound 32 integers under 108000",
        |b| {
            let mut rng = AesRng::new();
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
    c.bench_function("AesRng::rand 32 integers under 126", |b| {
        let mut rng = AesRng::new();
        let dist = Uniform::new(0, BOUND);
        b.iter(|| {
            for _ in 0..32 {
                black_box(dist.sample(&mut rng));
            }
        });
    });
    c.bench_function(
        "AesRng::uniform_integers_under_bound 32 integers under 126",
        |b| {
            let mut rng = AesRng::new();
            let dist = UniformIntegersUnderBound::new(BOUND);
            b.iter(|| {
                black_box(dist.sample(&mut rng));
                black_box(dist.sample(&mut rng));
            });
        },
    );
}

// NOTE: The CyclesPerByte is inaccurate, since it doesn't make any attempt to serialize execution.
// It only calls rdstc. Rather than trying to implement the right thing, we'll just increase the
// sample size and hope for the best.
criterion_group! {
    name = aesrng;
    config = Criterion::default().with_measurement(new_measurement()).sample_size(4096);
    targets = bench_aes_rand, bench_aes_rand_int_126, bench_aes_rand_int_108000
}
criterion_main!(aesrng);
