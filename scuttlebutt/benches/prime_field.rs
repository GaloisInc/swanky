use criterion::{criterion_group, criterion_main, Criterion};
use scuttlebutt::field::{F128p, FiniteField};

fn prime_field_add(c: &mut Criterion) {
    c.bench_function("prime_field_add", |b| {
        let x = F128p::random(&mut rand::thread_rng());
        let y = F128p::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x) + criterion::black_box(y)));
    });
}

fn prime_field_mul(c: &mut Criterion) {
    c.bench_function("prime_field_mul", |b| {
        let x = F128p::random(&mut rand::thread_rng());
        let y = F128p::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x) * criterion::black_box(y)));
    });
}

fn prime_field_inverse(c: &mut Criterion) {
    c.bench_function("prime_field_inverse", |b| {
        let x = F128p::random(&mut rand::thread_rng());
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
