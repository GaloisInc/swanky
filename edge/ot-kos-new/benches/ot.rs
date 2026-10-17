use criterion::{Criterion, criterion_group, criterion_main};

use swanky_ot_kos_new::KOS;
use swanky_ot_traits_new::{Receiver, Sender};

fn do_random_bench(c: &mut Criterion) {
    swanky_ot_test_new::bench::bench_random_ot::<KOS<Sender>, KOS<Receiver>>(c, 128);
}

fn do_standard_bench(c: &mut Criterion) {
    swanky_ot_test_new::bench::bench_block_ot::<KOS<Sender>, KOS<Receiver>>(c, 128);
}

criterion_group!(benches, do_standard_bench, do_random_bench,);
criterion_main!(benches);
