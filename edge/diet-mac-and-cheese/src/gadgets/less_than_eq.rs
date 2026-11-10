use crate::backend_trait::BackendT;
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;

/// A "less-than-or-equal" gadget for [`F2`].
///
/// This asserts that `a <= b`, where `a` contains MAC'd values, and `b` is
/// public.
pub(crate) fn less_than_eq_with_public<B: BackendT<FieldElement = F2>>(
    backend: &mut B,
    a: &[B::Wire],
    b: &[B::FieldElement],
    channel: &mut Channel,
) -> Result<()> {
    // act = 1;
    // r   = 0;
    // for i in 0..(n+1):
    //     act' = act(1+a+b)
    //     r'   = r + ((r+1) * act * a * (b+1))
    // assert_zero(r)
    assert_eq!(a.len(), b.len());

    let mut act = backend.input_public(F2::ONE)?;
    let mut r = backend.input_public(F2::ZERO)?;

    // data assumed provided in little-endian
    let l = a.len();
    for i in 0..a.len() {
        let a_i = a[l - i - 1];
        let b_i = b[l - i - 1];
        // (1+a+b)
        let a_plus_b = backend.add_constant(&a_i, b_i)?;
        let one_plus_a_plus_b = backend.add_constant(&a_plus_b, F2::ONE)?;

        // act' = act(1+a+b)
        let act_prime = backend.mul(&act, &one_plus_a_plus_b, channel)?;

        // r + 1
        let r_plus_one = backend.add_constant(&r, F2::ONE)?;

        // p1 = a * (b+1)
        let b_1 = b_i + F2::ONE;
        let p1 = backend.mul_constant(&a_i, b_1)?;

        // act * (a * (b+1))
        let act_times_p1 = backend.mul(&act, &p1, channel)?;

        // (r+1) * (act * (a * (b+1)))
        let p2 = backend.mul(&r_plus_one, &act_times_p1, channel)?;

        // r' = r + ((r+1) * act * a * (b+1))
        let r_prime = backend.add(&r, &p2)?;

        act = act_prime;
        r = r_prime;
    }

    backend.assert_zero(&r, channel)
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use swanky_channel::{Channel, local::local_channel_pair};
    use swanky_field::FiniteRing;
    use swanky_field_binary::{F2, F40b};
    use swanky_rng::SwankyRng;
    use swanky_svole_wykw::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};

    use crate::{
        DietMacAndCheese,
        backend_trait::BackendT,
        party::{Prover, Verifier},
        svole_trait::Svole,
    };

    use super::less_than_eq_with_public;

    #[test]
    fn less_than_eq_with_public_works() {
        fn run<B: BackendT<FieldElement = F2>>(
            party: &mut B,
            zero: B::Wire,
            one: B::Wire,
            channel: &mut Channel,
        ) {
            less_than_eq_with_public(party, &[zero], &[F2::ZERO], channel).unwrap();
            party.finalize(channel).unwrap();
            less_than_eq_with_public(party, &[zero], &[F2::ONE], channel).unwrap();
            party.finalize(channel).unwrap();
            less_than_eq_with_public(party, &[one], &[F2::ONE], channel).unwrap();
            party.finalize(channel).unwrap();
            less_than_eq_with_public(party, &[one], &[F2::ZERO], channel).unwrap();
            let _ = party.finalize(channel).unwrap_err();

            less_than_eq_with_public(party, &[zero], &[F2::ZERO], channel).unwrap();
            party.finalize(channel).unwrap();

            less_than_eq_with_public(
                party,
                &[one, one, zero],
                &[F2::ONE, F2::ONE, F2::ZERO],
                channel,
            )
            .unwrap();
            party.finalize(channel).unwrap();

            less_than_eq_with_public(
                party,
                &[one, one, one],
                &[F2::ONE, F2::ONE, F2::ZERO],
                channel,
            )
            .unwrap();
            let _ = party.finalize(channel).unwrap_err();

            less_than_eq_with_public(
                party,
                &[one, zero, zero],
                &[F2::ONE, F2::ZERO, F2::ONE],
                channel,
            )
            .unwrap();
            party.finalize(channel).unwrap();

            less_than_eq_with_public(
                party,
                &[one, one, one],
                &[F2::ONE, F2::ONE, F2::ONE],
                channel,
            )
            .unwrap();
            party.finalize(channel).unwrap();

            less_than_eq_with_public(
                party,
                &[one, zero, one, one],
                &[F2::ONE, F2::ZERO, F2::ZERO, F2::ONE],
                channel,
            )
            .unwrap();
            let _ = party.finalize(channel).unwrap_err();

            // that's testing the little-endianness of the function
            less_than_eq_with_public(party, &[one, one], &[F2::ZERO, F2::ONE], channel).unwrap();
            let _ = party.finalize(channel).unwrap_err();
        }
        local_channel_pair(
            |channel| {
                let rng = SwankyRng::from_seed(Default::default());
                let mut party = DietMacAndCheese::<Verifier, F2, F40b, Svole<_, _, _>>::init(
                    channel,
                    rng,
                    LPN_SETUP_SMALL,
                    LPN_EXTEND_SMALL,
                    false,
                )?;
                let zero = party.input_private(None, channel)?;
                let one = party.input_private(None, channel)?;

                run(&mut party, zero, one, channel);
                Ok(())
            },
            |channel| {
                let rng = SwankyRng::from_seed(Default::default());
                let mut party = DietMacAndCheese::<Prover, F2, F40b, Svole<_, _, _>>::init(
                    channel,
                    rng,
                    LPN_SETUP_SMALL,
                    LPN_EXTEND_SMALL,
                    false,
                )
                .unwrap();
                let zero = party.input_private(Some(F2::ZERO), channel)?;
                let one = party.input_private(Some(F2::ONE), channel)?;

                run(&mut party, zero, one, channel);
                Ok(())
            },
        )
        .unwrap();
    }
}
