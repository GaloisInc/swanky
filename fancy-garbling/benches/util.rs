use criterion::{criterion_group, criterion_main, Criterion};
use fancy_garbling::util;
use rand::Rng;
use std::time::Duration;

fn bench_tweak(c: &mut Criterion) {
    c.bench_function("util::tweak", move |b| {
        let rng = &mut rand::thread_rng();
        let i = rng.gen::<usize>();
        b.iter(|| {
            let block = util::tweak(i);
            criterion::black_box(block);
        });
    });
}

fn bench_tweak2(c: &mut Criterion) {
    c.bench_function("util::tweak2", move |b| {
        let rng = &mut rand::thread_rng();
        let i = rng.gen::<u64>();
        let j = rng.gen::<u64>();
        b.iter(|| {
            let block = util::tweak2(i, j);
            criterion::black_box(block);
        });
    });
}

fn bench_output_tweak(c: &mut Criterion) {
    c.bench_function("util::output_tweak", move |b| {
        let rng = &mut rand::thread_rng();
        let i = rng.gen::<usize>();
        let k = rng.gen::<u16>();
        b.iter(|| {
            let block = util::output_tweak(i, k);
            criterion::black_box(block);
        });
    });
}

fn base_q_add_eq(c: &mut Criterion, q: u16) {
    c.bench_function(&format!("util::as_base_q_add_eq ({})", q), move |b| {
        let rng = &mut rand::thread_rng();
        let x = rng.gen::<u128>();
        let mut xs = util::as_base_q_u128(x, q);
        let y = rng.gen::<u128>();
        let ys = util::as_base_q_u128(y, q);
        b.iter(|| {
            util::base_q_add_eq(&mut xs, &ys, q);
        });
    });
}

fn as_base_q_u128(c: &mut Criterion, q: u16) {
    c.bench_function(&format!("util::as_base_q_u128 ({})", q), move |b| {
        let rng = &mut rand::thread_rng();
        let x = rng.gen::<u128>();
        b.iter(|| {
            let ds = util::as_base_q_u128(x, q);
            criterion::black_box(ds);
        });
    });
}

fn from_base_q(c: &mut Criterion, q: u16) {
    c.bench_function(&format!("util::from_base_q ({})", q), move |b| {
        let rng = &mut rand::thread_rng();
        let x = rng.gen::<u128>();
        let ds = util::as_base_q_u128(x, q);
        b.iter(|| {
            let v = util::from_base_q(&ds, q);
            criterion::black_box(v);
        });
    });
}

fn u128_to_bits(c: &mut Criterion, n: usize) {
    c.bench_function(&format!("util::u128_to_bits ({})", n), move |b| {
        let rng = &mut rand::thread_rng();
        let x = rng.gen::<u128>();
        b.iter(|| {
            let bits = util::u128_to_bits(x, n);
            criterion::black_box(bits);
        });
    });
}

fn u128_from_bits(c: &mut Criterion, n: usize) {
    c.bench_function(&format!("util::u128_from_bits ({})", n), move |b| {
        let rng = &mut rand::thread_rng();
        let x = rng.gen::<u128>();
        let bits = util::u128_to_bits(x, n);
        b.iter(|| {
            let x = util::u128_from_bits(&bits);
            criterion::black_box(x);
        });
    });
}

fn bench_base_q_add_eq(c: &mut Criterion) {
    base_q_add_eq(c, 2);
    base_q_add_eq(c, 3);
    base_q_add_eq(c, 5);
    base_q_add_eq(c, 17);
}

fn bench_as_base_q_u128(c: &mut Criterion) {
    as_base_q_u128(c, 2);
    as_base_q_u128(c, 3);
    as_base_q_u128(c, 5);
    as_base_q_u128(c, 17);
}

fn bench_from_base_q(c: &mut Criterion) {
    from_base_q(c, 2);
    from_base_q(c, 3);
    from_base_q(c, 5);
    from_base_q(c, 17);
}

fn bench_u128_to_bits(c: &mut Criterion) {
    u128_to_bits(c, 128);
}

fn bench_u128_from_bits(c: &mut Criterion) {
    u128_from_bits(c, 128);
}

criterion_group! {
    name = util;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = bench_tweak, bench_tweak2, bench_output_tweak, bench_base_q_add_eq,
              bench_as_base_q_u128, bench_from_base_q, bench_u128_to_bits,
              bench_u128_from_bits,
}

criterion_main!(util);
