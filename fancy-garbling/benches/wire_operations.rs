use criterion::{criterion_group, criterion_main, Criterion};
use fancy_garbling::{util::RngExt, AllWire};
use scuttlebutt::{AesRng, Block};
use std::time::Duration;

use fancy_garbling::WireLabel;

fn bench_digits(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::digits ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let x = Block::from(rng.gen_u128());
        let w = AllWire::from_block(x, p);
        b.iter(|| {
            let digits = w.digits();
            criterion::black_box(digits);
        });
    });
}

fn bench_unpack(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::from_block ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let x = rng.gen_usable_block(p);
        b.iter(|| {
            let w = AllWire::from_block(x, p);
            criterion::black_box(w);
        });
    });
}

fn bench_pack(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::as_block ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let w = AllWire::rand(rng, p);
        b.iter(|| {
            let x = w.as_block();
            criterion::black_box(x);
        });
    });
}

fn bench_plus(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::plus ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let x = AllWire::rand(rng, p);
        let y = AllWire::rand(rng, p);
        b.iter(|| {
            let z = x.plus(&y);
            criterion::black_box(z);
        });
    });
}

fn bench_plus_eq(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::plus_eq ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let mut x = AllWire::rand(rng, p);
        let y = AllWire::rand(rng, p);
        b.iter(|| {
            let z = x.plus_eq(&y);
            criterion::black_box(z);
        });
    });
}

fn bench_minus(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::minus ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let x = AllWire::rand(rng, p);
        let y = AllWire::rand(rng, p);
        b.iter(|| {
            let z = x.minus(&y);
            criterion::black_box(z);
        });
    });
}

fn bench_minus_eq(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::minus_eq ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let mut x = AllWire::rand(rng, p);
        let y = AllWire::rand(rng, p);
        b.iter(|| {
            let z = x.minus_eq(&y);
            criterion::black_box(z);
        });
    });
}

fn bench_cmul(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::cmul ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let x = AllWire::rand(rng, p);
        let c = rng.gen_u16();
        b.iter(|| {
            let z = x.cmul(c);
            criterion::black_box(z);
        });
    });
}

fn bench_cmul_eq(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::cmul_eq ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let mut x = AllWire::rand(rng, p);
        let c = rng.gen_u16();
        b.iter(|| {
            let z = x.cmul_eq(c);
            criterion::black_box(z);
        });
    });
}

fn bench_negate(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::negate ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let x = AllWire::rand(rng, p);
        b.iter(|| {
            let z = x.negate();
            criterion::black_box(z);
        });
    });
}

fn bench_negate_eq(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::negate_eq ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let mut x = AllWire::rand(rng, p);
        b.iter(|| {
            let z = x.negate_eq();
            criterion::black_box(z);
        });
    });
}

fn bench_hash(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::hash ({})", p), move |b| {
        let rng = &mut rand::thread_rng();
        let tweak = rand::random::<Block>();
        let x = AllWire::rand(rng, p);
        b.iter(|| {
            let z = x.hash(tweak);
            criterion::black_box(z);
        });
    });
}

fn bench_hashback(c: &mut Criterion, q: u16) {
    c.bench_function(&format!("wire::hashback ({})", q), move |b| {
        let rng = &mut rand::thread_rng();
        let tweak = rand::random::<Block>();
        let wire = AllWire::rand(rng, q);
        b.iter(|| {
            let z = wire.hashback(tweak, q);
            criterion::black_box(z);
        });
    });
}

fn bench_zero(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::zero ({})", p), move |b| {
        b.iter(|| {
            let z = AllWire::zero(p);
            criterion::black_box(z);
        });
    });
}

fn bench_rand(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::rand ({})", p), move |b| {
        let rng = &mut AesRng::new();
        b.iter(|| {
            let z = AllWire::rand(rng, p);
            criterion::black_box(z);
        });
    });
}

fn bench_rand_delta(c: &mut Criterion, p: u16) {
    c.bench_function(&format!("wire::rand_delta ({})", p), move |b| {
        let rng = &mut AesRng::new();
        b.iter(|| {
            let z = AllWire::rand_delta(rng, p);
            criterion::black_box(z);
        });
    });
}

fn digits(c: &mut Criterion) {
    bench_digits(c, 2);
    bench_digits(c, 3);
    bench_digits(c, 5);
    bench_digits(c, 17);
}

fn unpack(c: &mut Criterion) {
    for q in 2..33 {
        bench_unpack(c, q);
    }
    bench_unpack(c, 113);
    bench_unpack(c, 257);
}
fn pack(c: &mut Criterion) {
    bench_pack(c, 2);
    bench_pack(c, 3);
    bench_pack(c, 5);
    bench_pack(c, 17);
}
fn plus(c: &mut Criterion) {
    bench_plus(c, 2);
    bench_plus(c, 3);
    bench_plus(c, 5);
    bench_plus(c, 17);
}
fn plus_eq(c: &mut Criterion) {
    bench_plus_eq(c, 2);
    bench_plus_eq(c, 3);
    bench_plus_eq(c, 5);
    bench_plus_eq(c, 17);
}
fn minus(c: &mut Criterion) {
    bench_minus(c, 2);
    bench_minus(c, 3);
    bench_minus(c, 5);
    bench_minus(c, 17);
}
fn minus_eq(c: &mut Criterion) {
    bench_minus_eq(c, 2);
    bench_minus_eq(c, 3);
    bench_minus_eq(c, 5);
    bench_minus_eq(c, 17);
}
fn cmul(c: &mut Criterion) {
    bench_cmul(c, 2);
    bench_cmul(c, 3);
    bench_cmul(c, 5);
    bench_cmul(c, 17);
}
fn cmul_eq(c: &mut Criterion) {
    bench_cmul_eq(c, 2);
    bench_cmul_eq(c, 3);
    bench_cmul_eq(c, 5);
    bench_cmul_eq(c, 17);
}
fn negate(c: &mut Criterion) {
    bench_negate(c, 2);
    bench_negate(c, 3);
    bench_negate(c, 5);
    bench_negate(c, 17);
}
fn negate_eq(c: &mut Criterion) {
    bench_negate_eq(c, 2);
    bench_negate_eq(c, 3);
    bench_negate_eq(c, 5);
    bench_negate_eq(c, 17);
}
fn hash(c: &mut Criterion) {
    bench_hash(c, 2);
    bench_hash(c, 3);
    bench_hash(c, 5);
    bench_hash(c, 17);
}
fn hashback(c: &mut Criterion) {
    bench_hashback(c, 2);
    bench_hashback(c, 3);
    bench_hashback(c, 5);
    bench_hashback(c, 17);
}
fn zero(c: &mut Criterion) {
    bench_zero(c, 2);
    bench_zero(c, 3);
    bench_zero(c, 5);
    bench_zero(c, 17);
}
fn rand(c: &mut Criterion) {
    bench_rand(c, 2);
    bench_rand(c, 3);
    bench_rand(c, 5);
    bench_rand(c, 17);
}
fn rand_delta(c: &mut Criterion) {
    bench_rand_delta(c, 2);
    bench_rand_delta(c, 3);
    bench_rand_delta(c, 5);
    bench_rand_delta(c, 17);
}

criterion_group! {
    name = wire_benches;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = digits, unpack, pack, plus, plus_eq, minus, minus_eq, cmul, cmul_eq, negate, negate_eq, hash, hashback, zero, rand, rand_delta
}

criterion_main!(wire_benches);
