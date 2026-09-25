//! Utilities to benchmark OT protocols using [`criterion`].
//!
//! **WARNING**: The benchmarking approach employed in this module has
//! limited accuracy due to spinning up new threads for each benchmark
//! iteration.

use criterion::Criterion;

use swanky_channel::local::local_channel_pair;
use swanky_field_binary::F2;
use swanky_ot_traits_new::{ObliviousTransfer, Receiver, Sender};
use swanky_party::{private::PartyPrivate, ty_eq::Witness};
use swanky_rng::SwankyRng;
use vectoreyes::U8x16;

use crate::rand_vec;

fn bench_block_ot_inner<
    OTSender: ObliviousTransfer<Sender>,
    OTReceiver: ObliviousTransfer<Receiver>,
>(
    bs: &[F2],
    ms: Vec<[U8x16; 2]>,
) {
    local_channel_pair(
        |c| {
            let mut rng = SwankyRng::new();
            let ot = OTSender::init(c, &mut rng).unwrap();

            ot.ot::<Vec<F2>, _, _, Vec<U8x16>>(
                PartyPrivate::empty(Witness::EQUAL_TYPES),
                PartyPrivate::new(ms.into_iter()),
                PartyPrivate::empty(Witness::EQUAL_TYPES),
                c,
                &mut rng,
            )
            .unwrap();

            Ok(())
        },
        |c| {
            let mut rng = SwankyRng::new();
            let ot = OTReceiver::init(c, &mut rng).unwrap();

            ot.ot::<_, Vec<[U8x16; 2]>, _, _>(
                PartyPrivate::new(bs.iter().copied()),
                PartyPrivate::empty(Witness::EQUAL_TYPES),
                PartyPrivate::new(&mut Vec::with_capacity(bs.len())),
                c,
                &mut rng,
            )
            .unwrap();

            Ok(())
        },
    )
    .unwrap();
}

/// Benchmark a 1-out-of-2 OT protocol using `size` inputs.
pub fn bench_block_ot<S: ObliviousTransfer<Sender>, R: ObliviousTransfer<Receiver>>(
    c: &mut Criterion,
    size: usize,
) {
    c.bench_function(
        &format!(
            "1-out-of-2 OT <{}, {}>",
            std::any::type_name::<S>(),
            std::any::type_name::<R>()
        ),
        |bench| {
            let m0s = rand_vec::<U8x16>(size);
            let m1s = rand_vec::<U8x16>(size);
            let ms: Vec<[U8x16; 2]> = m0s.into_iter().zip(m1s).map(|(m0, m1)| [m0, m1]).collect();
            let bs = rand_vec::<F2>(size);

            bench.iter(move || bench_block_ot_inner::<S, R>(&bs, ms.clone()))
        },
    );
}
