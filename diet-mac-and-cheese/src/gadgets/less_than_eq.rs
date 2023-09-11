use crate::backend_trait::BackendT;
use eyre::Result;
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
        let act_prime = backend.mul(&act, &one_plus_a_plus_b)?;

        // r + 1
        let r_plus_one = backend.add_constant(&r, F2::ONE)?;

        // p1 = a * (b+1)
        let b_1 = b_i + F2::ONE;
        let p1 = backend.mul_constant(&a_i, b_1)?;

        // act * (a * (b+1))
        let act_times_p1 = backend.mul(&act, &p1)?;

        // (r+1) * (act * (a * (b+1)))
        let p2 = backend.mul(&r_plus_one, &act_times_p1)?;

        // r' = r + ((r+1) * act * a * (b+1))
        let r_prime = backend.add(&r, &p2)?;

        act = act_prime;
        r = r_prime;
    }

    backend.assert_zero(&r)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    use ocelot::svole::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};
    use rand::SeedableRng;
    use scuttlebutt::{AesRng, Channel};
    use swanky_field::FiniteRing;
    use swanky_field_binary::{F40b, F2};

    use crate::{
        backend_trait::BackendT,
        svole_trait::{SvoleReceiver, SvoleSender},
        DietMacAndCheeseProver, DietMacAndCheeseVerifier,
    };

    use super::less_than_eq_with_public;

    #[test]
    fn less_than_eq_with_public_works() {
        fn run<B: BackendT<FieldElement = F2>>(party: &mut B, zero: B::Wire, one: B::Wire) {
            less_than_eq_with_public(party, &vec![zero], &vec![F2::ZERO]).unwrap();
            party.finalize().unwrap();
            less_than_eq_with_public(party, &vec![zero], &vec![F2::ONE]).unwrap();
            party.finalize().unwrap();
            less_than_eq_with_public(party, &vec![one], &vec![F2::ONE]).unwrap();
            party.finalize().unwrap();
            less_than_eq_with_public(party, &vec![one], &vec![F2::ZERO]).unwrap();
            let _ = party.finalize().unwrap_err();
            party.reset();

            less_than_eq_with_public(party, &vec![zero], &vec![F2::ZERO]).unwrap();
            party.finalize().unwrap();

            less_than_eq_with_public(
                party,
                &vec![one, one, zero],
                &vec![F2::ONE, F2::ONE, F2::ZERO],
            )
            .unwrap();
            party.finalize().unwrap();

            less_than_eq_with_public(
                party,
                &vec![one, one, one],
                &vec![F2::ONE, F2::ONE, F2::ZERO],
            )
            .unwrap();
            let _ = party.finalize().unwrap_err();
            party.reset();

            less_than_eq_with_public(
                party,
                &vec![one, zero, zero],
                &vec![F2::ONE, F2::ZERO, F2::ONE],
            )
            .unwrap();
            party.finalize().unwrap();

            less_than_eq_with_public(
                party,
                &vec![one, one, one],
                &vec![F2::ONE, F2::ONE, F2::ONE],
            )
            .unwrap();
            party.finalize().unwrap();

            less_than_eq_with_public(
                party,
                &vec![one, zero, one, one],
                &vec![F2::ONE, F2::ZERO, F2::ZERO, F2::ONE],
            )
            .unwrap();
            let _ = party.finalize().unwrap_err();
            party.reset();

            // that's testing the little-endianness of the function
            less_than_eq_with_public(party, &vec![one, one], &vec![F2::ZERO, F2::ONE]).unwrap();
            let _ = party.finalize().unwrap_err();
            party.reset();
        }
        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let rng = AesRng::from_seed(Default::default());
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);

            let mut party = DietMacAndCheeseProver::<F2, F40b, _, SvoleSender<F40b>>::init(
                &mut channel,
                rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
                false,
            )
            .unwrap();
            let zero = party.input_private(Some(F2::ZERO)).unwrap();
            let one = party.input_private(Some(F2::ONE)).unwrap();

            run(&mut party, zero, one);
        });

        let rng = AesRng::from_seed(Default::default());
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let mut party = DietMacAndCheeseVerifier::<F2, F40b, _, SvoleReceiver<F2, F40b>>::init(
            &mut channel,
            rng,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
            false,
        )
        .unwrap();
        let zero = party.input_private(None).unwrap();
        let one = party.input_private(None).unwrap();

        run(&mut party, zero, one);
        handle.join().unwrap();
    }
}
