use criterion::{criterion_group, criterion_main, Criterion};
use scuttlebutt::field::{FiniteField, Fp};

fn prime_field_add(c: &mut Criterion) {
    c.bench_function("prime_field_add", |b| {
        let x = Fp::random(&mut rand::thread_rng());
        let y = Fp::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x) + criterion::black_box(y)));
    });
}

fn prime_field_mul(c: &mut Criterion) {
    c.bench_function("prime_field_mul", |b| {
        let x = Fp::random(&mut rand::thread_rng());
        let y = Fp::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x) * criterion::black_box(y)));
    });
}

fn prime_field_inverse(c: &mut Criterion) {
    c.bench_function("prime_field_inverse", |b| {
        let x = Fp::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x).inverse()));
    });
}

criterion_group!(
    prime_field,
    prime_field_add,
    prime_field_mul,
    prime_field_inverse
);
criterion_main!(prime_field);
