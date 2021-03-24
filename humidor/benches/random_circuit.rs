use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand::distributions::{Standard, Distribution};
use ndarray::Array1;

use humidor::ligero::interactive;
use humidor::circuit::{Ckt, Op};

type Field = humidor::f2_19x3_26::F;

const MIN_SZ: u32 = 3;
const MAX_SZ: u32 = 3;

pub fn random_field_vec<R>(rng: &mut R, size: usize) -> Vec<Field>
    where R: rand::Rng
{
    (0 .. size).map(|_| rng.sample(rand::distributions::Standard)).collect()
}

fn random_ckt<R>(rng: &mut R, w: usize, c: usize) -> Ckt
    where R: rand::Rng
{
    let ops = (0..c).map(|n| {
        let i = rng.gen_range(0 .. w+n);
        let j = rng.gen_range(0 .. w+n);
        if rng.gen_bool(0.5) {
            Op::Add(i, j)
        } else {
            Op::Mul(i, j)
        }
    }).collect();

    Ckt { inp_size: w, ops }
}

pub fn bench_random_circuit(c: &mut Criterion) {
    let mut rng = StdRng::from_entropy();

    c.bench_function("random_circuit", |b| {
        let ckt = random_ckt(&mut rng, 20, 1000);
        let wit = random_field_vec(&mut rng, 20);

        b.iter(|| {
            let p = interactive::Prover::new(&ckt, &wit);
            let mut v = interactive::Verifier::new(&ckt);

            let r0 = p.round0();
            let r1 = v.round1(r0);
            let r2 = p.round2(r1);
            let r3 = v.round3(r2);
            p.round4(r3);
        })
    });
}

pub fn bench_prover_setup(c: &mut Criterion) {
    let mut rng = StdRng::from_entropy();

    let mut group = c.benchmark_group("Prover Setup");
    for s in MIN_SZ ..= MAX_SZ {
        let size = 10usize.pow(s);

        group.bench_with_input(BenchmarkId::new("Random Circuit", size),
            &size, |b, &size| {
                let ckt = random_ckt(&mut rng, 20, size);
                let wit = random_field_vec(&mut rng, 20);

                b.iter(|| interactive::Prover::new(&ckt, &wit));
            });
    }
    group.finish();
}

pub fn bench_verifier_setup(c: &mut Criterion) {
    let mut rng = StdRng::from_entropy();

    let mut group = c.benchmark_group("Verifier Setup");
    for s in MIN_SZ ..= MAX_SZ {
        let size = 10usize.pow(s);

        group.bench_with_input(BenchmarkId::new("Random Circuit", size),
            &size, |b, &size| {
                let ckt = random_ckt(&mut rng, 20, size);

                b.iter(|| interactive::Verifier::new(&ckt));
            });
    }
    group.finish();
}

pub fn bench_round0(c: &mut Criterion) {
    let mut rng = StdRng::from_entropy();

    let mut group = c.benchmark_group("Round 0");
    for s in MIN_SZ ..= MAX_SZ {
        let size = 10usize.pow(s);

        group.bench_with_input(BenchmarkId::new("Random Circuit", size),
            &size, |b, &size| {
                let ckt = random_ckt(&mut rng, 20, size);
                let wit = random_field_vec(&mut rng, 20);
                let p = interactive::Prover::new(&ckt, &wit);

                b.iter(|| p.round0());
            });
    }
    group.finish();
}

pub fn bench_round1(c: &mut Criterion) {
    let mut rng = StdRng::from_entropy();

    let mut group = c.benchmark_group("Round 1");
    for s in MIN_SZ ..= MAX_SZ {
        let size = 10usize.pow(s);

        group.bench_with_input(BenchmarkId::new("Random Circuit", s),
            &size, |b, &size| {
                let ckt = random_ckt(&mut rng, 20, size);
                let wit = random_field_vec(&mut rng, 20);
                let p = interactive::Prover::new(&ckt, &wit);
                let mut v = interactive::Verifier::new(&ckt);
                let r0 = p.round0();

                b.iter(|| v.round1(r0));
            });
    }
    group.finish();
}

pub fn bench_round2(c: &mut Criterion) {
    let mut rng = StdRng::from_entropy();

    let mut group = c.benchmark_group("Round 2");
    for s in MIN_SZ ..= MAX_SZ {
        let size = 10usize.pow(s);

        group.bench_with_input(BenchmarkId::new("Random Circuit", s),
            &size, |b, &size| {
                let ckt = random_ckt(&mut rng, 20, size);
                let wit = random_field_vec(&mut rng, 20);
                let p = interactive::Prover::new(&ckt, &wit);
                let mut v = interactive::Verifier::new(&ckt);
                let r0 = p.round0();
                let r1 = v.round1(r0);

                b.iter(|| p.round2(r1.clone()));
            });
    }
    group.finish();
}

pub fn bench_round3(c: &mut Criterion) {
    let mut rng = StdRng::from_entropy();

    let mut group = c.benchmark_group("Round 3");
    for s in MIN_SZ ..= MAX_SZ {
        let size = 10usize.pow(s);

        group.bench_with_input(BenchmarkId::new("Random Circuit", s),
            &size, |b, &size| {
                let ckt = random_ckt(&mut rng, 20, size);
                let wit = random_field_vec(&mut rng, 20);
                let p = interactive::Prover::new(&ckt, &wit);
                let mut v = interactive::Verifier::new(&ckt);
                let r0 = p.round0();
                let r1 = v.round1(r0);
                let r2 = p.round2(r1);

                b.iter(|| v.round3(r2.clone()));
            });
    }
    group.finish();
}

pub fn bench_round4(c: &mut Criterion) {
    let mut rng = StdRng::from_entropy();

    let mut group = c.benchmark_group("Round 4");
    for s in MIN_SZ ..= MAX_SZ {
        let size = 10usize.pow(s);

        group.bench_with_input(BenchmarkId::new("Random Circuit", s),
            &size, |b, &size| {
                let ckt = random_ckt(&mut rng, 20, size);
                let wit = random_field_vec(&mut rng, 20);
                let p = interactive::Prover::new(&ckt, &wit);
                let mut v = interactive::Verifier::new(&ckt);
                let r0 = p.round0();
                let r1 = v.round1(r0);
                let r2 = p.round2(r1);
                let r3 = v.round3(r2);

                b.iter(|| p.round4(r3.clone()));
            });
    }
    group.finish();
}

pub fn bench_verify(c: &mut Criterion) {
    let mut rng = StdRng::from_entropy();

    let mut group = c.benchmark_group("Verify");
    for s in MIN_SZ ..= MAX_SZ {
        let size = 10usize.pow(s);

        group.bench_with_input(BenchmarkId::new("Random Circuit", s),
            &size, |b, &size| {
                let ckt = random_ckt(&mut rng, 20, size);
                let wit = random_field_vec(&mut rng, 20);
                let p = interactive::Prover::new(&ckt, &wit);
                let mut v = interactive::Verifier::new(&ckt);
                let r0 = p.round0();
                let r1 = v.round1(r0);
                let r2 = p.round2(r1);
                let r3 = v.round3(r2);
                let r4 = p.round4(r3);

                b.iter(|| v.verify(r4.clone()));
            });
    }
    group.finish();
}

criterion_group!{
    name = random_circuit;
    config = Criterion::default();
    targets = bench_random_circuit //bench_prover_setup, bench_verifier_setup, bench_round0, bench_round1, bench_round2, bench_round3, bench_round4, bench_verify
}
criterion_main!(random_circuit);
