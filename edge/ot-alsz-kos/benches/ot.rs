use criterion::{Criterion, criterion_group, criterion_main};
use swanky_ot_traits::{
    CorrelatedReceiver, CorrelatedSender, RandomReceiver, RandomSender, Receiver, Sender,
};
use vectoreyes::U8x16;
fn do_bench<
    S: Sender<Msg = U8x16> + CorrelatedSender + RandomSender,
    R: Receiver<Msg = U8x16> + CorrelatedReceiver + RandomReceiver,
>(
    c: &mut Criterion,
) {
    swanky_ot_test::bench::bench_block_ot::<S, R>(c, 128);
    swanky_ot_test::bench::bench_random_ot::<S, R>(c, 128);
    swanky_ot_test::bench::bench_correlated_ot::<S, R>(c, 128);
}
criterion_group!(
    benches,
    do_bench::<swanky_ot_alsz_kos::alsz::Sender, swanky_ot_alsz_kos::alsz::Receiver>,
    do_bench::<swanky_ot_alsz_kos::kos::Sender, swanky_ot_alsz_kos::kos::Receiver>,
);
criterion_main!(benches);
