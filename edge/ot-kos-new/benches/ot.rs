use criterion::{Criterion, criterion_group, criterion_main};

use swanky_ot_kos_new::KOS;
use swanky_ot_traits_new::{Receiver, Sender};

fn do_random_bench_pow_2_10(c: &mut Criterion) {
    swanky_ot_test_new::bench::bench_random_ot::<KOS<Sender>, KOS<Receiver>>(c, 1 << 10);
}

fn do_random_bench_pow_2_20(c: &mut Criterion) {
    swanky_ot_test_new::bench::bench_random_ot::<KOS<Sender>, KOS<Receiver>>(c, 1 << 20);
}

fn do_standard_bench_pow_2_10(c: &mut Criterion) {
    swanky_ot_test_new::bench::bench_block_ot::<KOS<Sender>, KOS<Receiver>>(c, 1 << 10);
}

fn do_standard_bench_pow_2_20(c: &mut Criterion) {
    swanky_ot_test_new::bench::bench_block_ot::<KOS<Sender>, KOS<Receiver>>(c, 1 << 20);
}

criterion_group!(
    benches,
    do_standard_bench_pow_2_10,
    do_standard_bench_pow_2_20,
    do_random_bench_pow_2_10,
    do_random_bench_pow_2_20,
);
criterion_main!(benches);
