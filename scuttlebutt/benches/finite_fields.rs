macro_rules! finite_field_benchmarks {
    (
        $name: ident,
        $field: ty,
    ) => {
        mod $name {
            use criterion::{black_box, criterion_group, Criterion};
            use scuttlebutt::field::FiniteField;
            use scuttlebutt::ring::FiniteRing;
            use scuttlebutt::AesRng;

            fn add(c: &mut Criterion) {
                c.bench_function(&format!("{}::add", stringify!($field)), |b| {
                    let x = <$field>::random(&mut rand::thread_rng());
                    let y = <$field>::random(&mut rand::thread_rng());
                    b.iter(|| black_box(black_box(x) + black_box(y)));
                });
            }

            fn mul(c: &mut Criterion) {
                c.bench_function(&format!("{}::mul", stringify!($field)), |b| {
                    let x = <$field>::random(&mut rand::thread_rng());
                    let y = <$field>::random(&mut rand::thread_rng());
                    b.iter(|| black_box(black_box(x) * black_box(y)));
                });
            }

            fn div(c: &mut Criterion) {
                c.bench_function(&format!("{}::div", stringify!($field)), |b| {
                    let x = <$field>::random(&mut rand::thread_rng());
                    let y = <$field>::random_nonzero(&mut rand::thread_rng());
                    b.iter(|| black_box(black_box(x) / black_box(y)));
                });
            }

            fn pow(c: &mut Criterion) {
                c.bench_function(&format!("{}::pow32", stringify!($field)), |b| {
                    let x = <$field>::random(&mut rand::thread_rng());
                    b.iter(|| black_box(black_box(x).pow(black_box(32u128))));
                });
            }

            fn inverse(c: &mut Criterion) {
                c.bench_function(&format!("{}::inverse", stringify!($field)), |b| {
                    let x = <$field>::random_nonzero(&mut rand::thread_rng());
                    b.iter(|| black_box(black_box(x).inverse()));
                });
            }

            fn random(c: &mut Criterion) {
                c.bench_function(&format!("{}::random", stringify!($field)), |b| {
                    let mut rng = AesRng::new();
                    b.iter(|| black_box(<$field>::random(&mut rng)));
                });
            }

            fn sum(c: &mut Criterion) {
                c.bench_function(&format!("{}::sum100", stringify!($field)), |b| {
                    let x: Vec<_> = (0..100)
                        .map(|_| <$field>::random(&mut rand::thread_rng()))
                        .collect();
                    b.iter(|| black_box(black_box(x.iter().copied()).sum::<$field>()));
                });
            }

            fn product(c: &mut Criterion) {
                c.bench_function(&format!("{}::prod100", stringify!($field)), |b| {
                    let x: Vec<_> = (0..100)
                        .map(|_| <$field>::random(&mut rand::thread_rng()))
                        .collect();
                    b.iter(|| black_box(black_box(x.iter().copied()).product::<$field>()));
                });
            }

            criterion_group!($name, add, mul, div, pow, inverse, random, sum, product);
        }
    };
}

finite_field_benchmarks!(f2, scuttlebutt::field::F2,);
finite_field_benchmarks!(f61p, scuttlebutt::field::F61p,);
finite_field_benchmarks!(f64b, scuttlebutt::field::F64b,);
finite_field_benchmarks!(f128b, scuttlebutt::field::F128b,);

finite_field_benchmarks!(f40b, scuttlebutt::field::F40b,);
finite_field_benchmarks!(f45b, scuttlebutt::field::F45b,);
finite_field_benchmarks!(f56b, scuttlebutt::field::F56b,);
finite_field_benchmarks!(f63b, scuttlebutt::field::F63b,);

#[cfg(feature = "ff")]
finite_field_benchmarks!(f2e19x3e26, scuttlebutt::field::F2e19x3e26,);
#[cfg(feature = "ff")]
finite_field_benchmarks!(f128p, scuttlebutt::field::F128p,);
#[cfg(feature = "ff")]
finite_field_benchmarks!(f256p, scuttlebutt::field::F256p,);
#[cfg(feature = "ff")]
finite_field_benchmarks!(f384p, scuttlebutt::field::F384p,);
#[cfg(feature = "ff")]
finite_field_benchmarks!(f384q, scuttlebutt::field::F384q,);
#[cfg(feature = "ff")]
finite_field_benchmarks!(fbls12381, scuttlebutt::field::Fbls12381,);
#[cfg(feature = "ff")]
finite_field_benchmarks!(fbn254, scuttlebutt::field::Fbn254,);

// XXX: Is there a better way to do this?
#[cfg(not(feature = "ff"))]
criterion::criterion_main!(
    f2::f2,
    f61p::f61p,
    f64b::f64b,
    f128b::f128b,
    f40b::f40b,
    f45b::f45b,
    f56b::f56b,
    f63b::f63b,
);
#[cfg(feature = "ff")]
criterion::criterion_main!(
    f2::f2,
    f61p::f61p,
    f64b::f64b,
    f128b::f128b,
    f40b::f40b,
    f45b::f45b,
    f56b::f56b,
    f63b::f63b,
    // `ff` specific fields
    f2e19x3e26::f2e19x3e26,
    f128p::f128p,
    f256p::f256p,
    f384p::f384p,
    f384q::f384q,
    fbls12381::fbls12381,
    fbn254::fbn254
);
