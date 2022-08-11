use criterion::{criterion_group, criterion_main, Criterion};
use scuttlebutt::field::{F128b, FiniteField};

fn gf_2_128_add(c: &mut Criterion) {
    c.bench_function("gf_2_128_add", |b| {
        let x = F128b::random(&mut rand::thread_rng());
        let y = F128b::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x) + criterion::black_box(y)));
    });
}

fn gf_2_128_mul(c: &mut Criterion) {
    c.bench_function("gf_2_128_mul", |b| {
        let x = F128b::random(&mut rand::thread_rng());
        let y = F128b::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x) * criterion::black_box(y)));
    });
}

fn gf_2_128_inverse(c: &mut Criterion) {
    c.bench_function("gf_2_128_inverse", |b| {
        let x = F128b::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x).inverse()));
    });
}

criterion_group!(gf_2_128, gf_2_128_add, gf_2_128_mul, gf_2_128_inverse);
criterion_main!(gf_2_128);
