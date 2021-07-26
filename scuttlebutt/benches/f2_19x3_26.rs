use criterion::{criterion_group, criterion_main, Criterion};
use scuttlebutt::field::{F2_19x3_26, FiniteField};

fn f2_19x3_26_add(c: &mut Criterion) {
    c.bench_function("f2_19x3_26_add", |b| {
        let x = F2_19x3_26::random(&mut rand::thread_rng());
        let y = F2_19x3_26::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x) + criterion::black_box(y)));
    });
}

fn f2_19x3_26_mul(c: &mut Criterion) {
    c.bench_function("f2_19x3_26_mul", |b| {
        let x = F2_19x3_26::random(&mut rand::thread_rng());
        let y = F2_19x3_26::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x) * criterion::black_box(y)));
    });
}

fn f2_19x3_26_inverse(c: &mut Criterion) {
    c.bench_function("f2_19x3_26_inverse", |b| {
        let x = F2_19x3_26::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x).inverse()));
    });
}

fn f2_19x3_26_sum(c: &mut Criterion) {
    c.bench_function("f2_19x3_26_sum10", |b| {
        let x: Vec<_> = (0..10)
            .map(|_| F2_19x3_26::random(&mut rand::thread_rng()))
            .collect();
        b.iter(|| criterion::black_box(criterion::black_box(x.iter().copied()).sum::<F2_19x3_26>()));
    });
    c.bench_function("f2_19x3_26_sum100", |b| {
        let x: Vec<_> = (0..100)
            .map(|_| F2_19x3_26::random(&mut rand::thread_rng()))
            .collect();
        b.iter(|| criterion::black_box(criterion::black_box(x.iter().copied()).sum::<F2_19x3_26>()));
    });
    c.bench_function("f2_19x3_26_sum1000", |b| {
        let x: Vec<_> = (0..1000)
            .map(|_| F2_19x3_26::random(&mut rand::thread_rng()))
            .collect();
        b.iter(|| criterion::black_box(criterion::black_box(x.iter().copied()).sum::<F2_19x3_26>()));
    });
}

criterion_group!(f2_19x3_26, f2_19x3_26_add, f2_19x3_26_mul, f2_19x3_26_inverse, f2_19x3_26_sum);
criterion_main!(f2_19x3_26);
