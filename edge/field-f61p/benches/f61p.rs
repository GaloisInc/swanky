use criterion::criterion_main;

use swanky_field_f61p::F61p;
use swanky_field_test::bench_field;

bench_field!(f61p, F61p);

criterion_main!(f61p::f61p);
