use criterion::{Criterion, criterion_group, criterion_main};

use swanky_ot_chou_orlandi_new::ChouOrlandi;
use swanky_ot_traits_new::{Receiver, Sender};

fn do_bench(c: &mut Criterion) {
    swanky_ot_test_new::bench::bench_random_ot::<ChouOrlandi<Sender>, ChouOrlandi<Receiver>>(
        c, 128,
    );
}

criterion_group!(benches, do_bench,);
criterion_main!(benches);
