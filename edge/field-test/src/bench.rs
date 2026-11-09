/// Benchmark finite field operations.
///
/// To use this, run `swanky_field_test::bench_field!(benchmark,
/// MyFunField)` where `benchmark` is an arbitrary module name used to
/// namespace the benchmarks / name the `criterion` benchmarking
/// group, and `MyFunField` is the field to benchmark.
///
/// Then, run `criterion::criterion_main!(benchmark::benchmark)` to
/// generate a `criterion`-compatible `main` function that will
/// execute the benchmarks.
/// This can be given a list of groups, so you can invoke
/// `swanky_field_test::bench_field!` as many times as you want, and
/// pass all of the given `benchmark` names at once.
///
/// Of course, this should all be done in a benchmarking file, with
/// the appropriate changes to `Cargo.toml` to run it as a benchmark.
#[macro_export]
macro_rules! bench_field {
    ($bench_name:ident, $fe:ty) => {
        mod $bench_name {
            use super::*;
            type FE = $fe;

            // Make benches a separate module, so `use super::*;`
            // doesn't pollute the benchmarking module namespace.
            // We need it above, because `$fe` might be an unqualified
            // name.
            mod benches {
                use super::FE;
                use $crate::__internal_macro_exports::{criterion, swanky_field, swanky_rng};

                use std::hint::black_box;

                use criterion::{BatchSize, Criterion, criterion_group};

                use swanky_field::{FiniteField, FiniteRing};
                use swanky_rng::SwankyRng;

                pub fn add(c: &mut Criterion) {
                    c.bench_function(&format!("{}::add", std::any::type_name::<FE>()), |b| {
                        b.iter_batched(
                            || {
                                (
                                    <FE>::random(&mut rand::rng()),
                                    <FE>::random(&mut rand::rng()),
                                )
                            },
                            |(x, y)| {
                                black_box(black_box(x) + black_box(y));
                            },
                            BatchSize::SmallInput,
                        );
                    });
                }

                pub fn mul(c: &mut Criterion) {
                    c.bench_function(&format!("{}::mul", std::any::type_name::<FE>()), |b| {
                        b.iter_batched(
                            || {
                                (
                                    <FE>::random(&mut rand::rng()),
                                    <FE>::random(&mut rand::rng()),
                                )
                            },
                            |(x, y)| {
                                black_box(black_box(x) * black_box(y));
                            },
                            BatchSize::SmallInput,
                        );
                    });
                }

                pub fn div(c: &mut Criterion) {
                    c.bench_function(&format!("{}::div", std::any::type_name::<FE>()), |b| {
                        b.iter_batched(
                            || {
                                (
                                    <FE>::random(&mut rand::rng()),
                                    <FE>::random(&mut rand::rng()),
                                )
                            },
                            |(x, y)| {
                                black_box(black_box(x) / black_box(y));
                            },
                            BatchSize::SmallInput,
                        );
                    });
                }

                pub fn pow(c: &mut Criterion) {
                    c.bench_function(&format!("{}::pow32", std::any::type_name::<FE>()), |b| {
                        b.iter_batched(
                            || <FE>::random(&mut rand::rng()),
                            |x| {
                                black_box(black_box(x).pow(black_box(32u128)));
                            },
                            BatchSize::SmallInput,
                        );
                    });
                }

                pub fn inverse(c: &mut Criterion) {
                    c.bench_function(&format!("{}::inverse", std::any::type_name::<FE>()), |b| {
                        b.iter_batched(
                            || <FE>::random(&mut rand::rng()),
                            |x| {
                                black_box(black_box(x).inverse());
                            },
                            BatchSize::SmallInput,
                        );
                    });
                }

                pub fn random(c: &mut Criterion) {
                    c.bench_function(&format!("{}::random", std::any::type_name::<FE>()), |b| {
                        b.iter_batched(
                            || SwankyRng::new(),
                            |mut rng| {
                                black_box(<FE>::random(&mut rng));
                            },
                            BatchSize::SmallInput,
                        );
                    });
                }

                pub fn sum(c: &mut Criterion) {
                    c.bench_function(&format!("{}::sum100", std::any::type_name::<FE>()), |b| {
                        b.iter_batched(
                            || {
                                (0..100)
                                    .map(|_| <FE>::random(&mut rand::rng()))
                                    .collect::<Vec<_>>()
                            },
                            |x| {
                                black_box(black_box(x.iter().copied()).sum::<FE>());
                            },
                            BatchSize::SmallInput,
                        );
                    });
                }

                pub fn product(c: &mut Criterion) {
                    c.bench_function(&format!("{}::prod100", std::any::type_name::<FE>()), |b| {
                        b.iter_batched(
                            || {
                                (0..100)
                                    .map(|_| <FE>::random(&mut rand::rng()))
                                    .collect::<Vec<_>>()
                            },
                            |x| {
                                black_box(black_box(x.iter().copied()).product::<FE>());
                            },
                            BatchSize::SmallInput,
                        );
                    });
                }
            }

            $crate::__internal_macro_exports::criterion::criterion_group!(
                $bench_name,
                benches::add,
                benches::mul,
                benches::div,
                benches::pow,
                benches::inverse,
                benches::random,
                benches::sum,
                benches::product
            );
        }
    };
}
