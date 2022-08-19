use criterion::{criterion_group, criterion_main, Criterion};
use scuttlebutt::{
    field::{F40b, FiniteField},
    AesRng,
};

fn gf_2_40_add(c: &mut Criterion) {
    c.bench_function("gf_2_40_add", |b| {
        let x = F40b::random(&mut rand::thread_rng());
        let y = F40b::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x) + criterion::black_box(y)));
    });
}

fn gf_2_40_mul(c: &mut Criterion) {
    c.bench_function("gf_2_40_mul", |b| {
        let x = F40b::random(&mut rand::thread_rng());
        let y = F40b::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x) * criterion::black_box(y)));
    });
}

fn gf_2_40_rand(c: &mut Criterion) {
    c.bench_function("gf_2_40_rand", |b| {
        let mut rng = AesRng::new();
        b.iter(|| criterion::black_box(F40b::random(&mut rng)));
    });
}

fn gf_2_40_inverse(c: &mut Criterion) {
    c.bench_function("gf_2_40_inverse", |b| {
        let x = F40b::random(&mut rand::thread_rng());
        b.iter(|| criterion::black_box(criterion::black_box(x).inverse()));
    });
}

criterion_group!(
    gf_2_40,
    gf_2_40_add,
    gf_2_40_mul,
    gf_2_40_rand,
    gf_2_40_inverse
);
criterion_main!(gf_2_40);
