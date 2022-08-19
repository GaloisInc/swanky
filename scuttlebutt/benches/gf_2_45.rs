use criterion::{criterion_group, criterion_main, Criterion};
use scuttlebutt::field::{F45b, FiniteField};

fn gf_2_45_add(c: &mut Criterion) {
    c.bench_function("gf_2_45_add", |b| {
        let x = F45b::random(&mut rand::thread_rng());
        let y = F45b::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x) + criterion::black_box(y)));
    });
}

fn gf_2_45_mul(c: &mut Criterion) {
    c.bench_function("gf_2_45_mul", |b| {
        let x = F45b::random(&mut rand::thread_rng());
        let y = F45b::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x) * criterion::black_box(y)));
    });
}

fn gf_2_45_inverse(c: &mut Criterion) {
    c.bench_function("gf_2_45_inverse", |b| {
        let x = F45b::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x).inverse()));
    });
}

criterion_group!(gf_2_45, gf_2_45_add, gf_2_45_mul, gf_2_45_inverse);
criterion_main!(gf_2_45);
