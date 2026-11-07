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
    () => {};
}
