#![deny(missing_docs)]
//! Testing utilities for oblivious transfer protocols

use rand::{
    RngExt,
    distr::{Distribution, StandardUniform},
};

use swanky_channel::local::local_channel_pair;
use swanky_field_binary::F2;
use swanky_ot_traits_new::{OTCorrelated, OTRandom, ObliviousTransfer, Receiver, Sender};
use swanky_party::{either::PartyEither, private::PartyPrivate, ty_eq::Witness};
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

/// Test the functionality of a Correlated OT protocol by OT-int
/// `ninputs` blocks.
pub fn test_cotext<OTSender: OTCorrelated<Sender>, OTReceiver: OTCorrelated<Receiver>>(
    ninputs: usize,
) {
    let delta = rand::random::<U8x16>();

    let bs = rand_vec::<F2>(ninputs);

    let mut out_s: Vec<PartyEither<Sender, U8x16, U8x16>> = Vec::with_capacity(ninputs);
    let mut out_r: Vec<PartyEither<Receiver, U8x16, U8x16>> = Vec::with_capacity(ninputs);

    local_channel_pair(
        |c| {
            let mut rng = SwankyRng::new();
            let otext = OTSender::init(c, &mut rng).unwrap();

            otext
                .ot_correlated::<Vec<F2>, _>(
                    PartyEither::new(Witness::EQUAL_TYPES, ninputs),
                    PartyPrivate::new(delta),
                    &mut out_s,
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
                .ot_correlated(
                    PartyEither::new(Witness::EQUAL_TYPES, bs.iter().copied()),
                    PartyPrivate::empty(Witness::EQUAL_TYPES),
                    &mut out_r,
                    c,
                    &mut rng,
                )
                .unwrap();

            Ok(())
        },
    )
    .unwrap();

    for i in 0..ninputs {
        assert_eq!(
            *out_r[i].as_ref().into_inner(Witness::EQUAL_TYPES),
            if bs[i].into() {
                *out_s[i].as_ref().into_inner(Witness::EQUAL_TYPES) ^ delta
            } else {
                *out_s[i].as_ref().into_inner(Witness::EQUAL_TYPES)
            }
        );
    }
}

/// Test the functionality of a Random OT protocol by OT-int `ninputs`
/// blocks.
pub fn test_rotext<OTSender: OTRandom<Sender>, OTReceiver: OTRandom<Receiver>>(ninputs: usize) {
    let bs = rand_vec::<F2>(ninputs);

    let mut out_s: Vec<PartyEither<Sender, [U8x16; 2], U8x16>> = Vec::with_capacity(ninputs);
    let mut out_r: Vec<PartyEither<Receiver, [U8x16; 2], U8x16>> = Vec::with_capacity(ninputs);

    local_channel_pair(
        |c| {
            let mut rng = SwankyRng::new();
            let otext = OTSender::init(c, &mut rng).unwrap();

            otext
                .ot_random::<Vec<F2>, _>(
                    PartyEither::new(Witness::EQUAL_TYPES, ninputs),
                    &mut out_s,
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
                .ot_random(
                    PartyEither::new(Witness::EQUAL_TYPES, bs.iter().copied()),
                    &mut out_r,
                    c,
                    &mut rng,
                )
                .unwrap();

            Ok(())
        },
    )
    .unwrap();

    for i in 0..ninputs {
        assert_eq!(
            *out_r[i].as_ref().into_inner(Witness::EQUAL_TYPES),
            if bs[i].into() {
                out_s[i].as_ref().into_inner(Witness::EQUAL_TYPES)[1]
            } else {
                out_s[i].as_ref().into_inner(Witness::EQUAL_TYPES)[0]
            }
        );
    }
}
