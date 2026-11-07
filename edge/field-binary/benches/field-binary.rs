use criterion::criterion_main;

use swanky_field_binary::{F2, F8b, F40b, F45b, F56b, F63b, F64b, F128b, F256b};
use swanky_field_test::bench_field;

bench_field!(f2, F2);
bench_field!(f8b, F8b);
bench_field!(f40b, F40b);
bench_field!(f45b, F45b);
bench_field!(f56b, F56b);
bench_field!(f63b, F63b);
bench_field!(f64b, F64b);
bench_field!(f128b, F128b);
bench_field!(f256b, F256b);

criterion_main!(
    f2::f2,
    f8b::f8b,
    f40b::f40b,
    f45b::f45b,
    f56b::f56b,
    f63b::f63b,
    f64b::f64b,
    f128b::f128b,
    f256b::f256b
);
