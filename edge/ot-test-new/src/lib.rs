#![deny(missing_docs)]
//! Testing utilities for oblivious transfer protocols

use rand::{
    RngExt,
    distr::{Distribution, StandardUniform},
};

use swanky_channel::local::local_channel_pair;
use swanky_field_binary::F2;
use swanky_ot_traits_new::{ObliviousTransfer, Receiver, Sender};
use swanky_party::{private::PartyPrivate, ty_eq::Witness};
use swanky_rng::SwankyRng;
use vectoreyes::U8x16;

fn rand_vec<T>(size: usize) -> Vec<T>
where
    StandardUniform: Distribution<T>,
{
    let mut rng = rand::rng();
    (0..size).map(|_| rng.random::<T>()).collect()
}

/// Test the functionality of an OT protocol by OT-ing `ninputs`
/// blocks.
pub fn test_otext<OTSender: ObliviousTransfer<Sender>, OTReceiver: ObliviousTransfer<Receiver>>(
    ninputs: usize,
) {
    let m0s = rand_vec::<U8x16>(ninputs);
    let m1s = rand_vec::<U8x16>(ninputs);

    let bs = rand_vec::<F2>(ninputs);

    let mut res: Vec<U8x16> = Vec::with_capacity(ninputs);

    local_channel_pair(
        |c| {
            let mut rng = SwankyRng::new();
            let otext = OTSender::init(c, &mut rng).unwrap();

            otext
                .ot::<Vec<F2>, _, _, Vec<U8x16>>(
                    PartyPrivate::empty(Witness::EQUAL_TYPES),
                    PartyPrivate::new(m0s.iter().zip(m1s.iter()).map(|(&x, &y)| [x, y])),
                    PartyPrivate::empty(Witness::EQUAL_TYPES),
                    c,
                    &mut rng,
                )
                .unwrap();

            Ok(())
        },
        |c| {
            let mut rng = SwankyRng::new();
            let otext = OTReceiver::init(c, &mut rng).unwrap();

            otext
                .ot::<_, Vec<[U8x16; 2]>, _, _>(
                    PartyPrivate::new(bs.iter().copied()),
                    PartyPrivate::empty(Witness::EQUAL_TYPES),
                    PartyPrivate::new(&mut res),
                    c,
                    &mut rng,
                )
                .unwrap();

            Ok(())
        },
    )
    .unwrap();

    for i in 0..ninputs {
        assert_eq!(res[i], if bs[i].into() { m1s[i] } else { m0s[i] });
    }
}
