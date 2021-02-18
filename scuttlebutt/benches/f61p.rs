use criterion::{criterion_group, criterion_main, Criterion};
use scuttlebutt::field::{F61p, FiniteField};

fn f61p_add(c: &mut Criterion) {
    c.bench_function("f61p_add", |b| {
        let x = F61p::random(&mut rand::thread_rng());
        let y = F61p::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x) + criterion::black_box(y)));
    });
}

fn f61p_mul(c: &mut Criterion) {
    c.bench_function("f61p_mul", |b| {
        let x = F61p::random(&mut rand::thread_rng());
        let y = F61p::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x) * criterion::black_box(y)));
    });
}

fn f61p_inverse(c: &mut Criterion) {
    c.bench_function("f61p_inverse", |b| {
        let x = F61p::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x).inverse()));
    });
}

fn f61p_sum(c: &mut Criterion) {
    c.bench_function("f61p_sum10", |b| {
        let x: Vec<_> = (0..10)
            .map(|_| F61p::random(&mut rand::thread_rng()))
            .collect();
        b.iter(|| criterion::black_box(criterion::black_box(x.iter().copied()).sum::<F61p>()));
    });
    c.bench_function("f61p_sum100", |b| {
        let x: Vec<_> = (0..100)
            .map(|_| F61p::random(&mut rand::thread_rng()))
            .collect();
        b.iter(|| criterion::black_box(criterion::black_box(x.iter().copied()).sum::<F61p>()));
    });
    c.bench_function("f61p_sum1000", |b| {
        let x: Vec<_> = (0..1000)
            .map(|_| F61p::random(&mut rand::thread_rng()))
            .collect();
        b.iter(|| criterion::black_box(criterion::black_box(x.iter().copied()).sum::<F61p>()));
    });
}

criterion_group!(f61p, f61p_add, f61p_mul, f61p_inverse, f61p_sum);
criterion_main!(f61p);
