use crate::{
    backend_multifield::BackendLiftT, backend_trait::BackendT, gadgets::dotproduct_with_public,
    mac::Mac,
};
use eyre::{ensure, Result};
use generic_array::{typenum::Unsigned, GenericArray};
use scuttlebutt::generic_array_length::Arr;
use swanky_field::{DegreeModulo, FiniteField, FiniteRing, IsSubFieldOf};
use swanky_field_binary::F2;

/// A permutation check gadget that asserts that `xs = 𝛑(ys)`, erroring out if
/// not.
///
/// This gadget currently only works over fields larger than the statistical
/// security parameter (which we have harded at 40 bits).
pub(crate) fn permutation_check<B: BackendT>(
    backend: &mut B,
    xs: &[B::Wire],
    ys: &[B::Wire],
    ntuples: usize,
    tuple_size: usize,
) -> Result<()> {
    ensure!(
        <B::FieldElement as FiniteField>::NumberOfBitsInBitDecomposition::USIZE >= 40,
        "Field size must be >= 40 bits"
    );

    ensure!(xs.len() == ys.len(), "Input lengths are not equal",);
    ensure!(
        xs.len() == ntuples * tuple_size,
        "Provided input length not equal to expected input length",
    );

    let minus_one = -B::FieldElement::ONE;
    let random = backend.random()?;

    // TODO: Better would be to generate random values using `random` as a seed.
    let mut acc = random;
    let mut challenges = vec![B::FieldElement::ZERO; tuple_size];
    for challenge in challenges.iter_mut() {
        *challenge = acc;
        acc = acc * random;
    }

    let challenge = backend.random()?;

    let mut x = backend.constant(B::FieldElement::ONE)?;
    for i in 0..ntuples {
        let result = dotproduct_with_public::<B>(
            backend,
            &xs[i * tuple_size..(i + 1) * tuple_size],
            &challenges,
        )?;
        let tmp = backend.add_constant(&result, challenge * minus_one)?;
        x = backend.mul(&x, &tmp)?;
    }
    let mut y = backend.constant(B::FieldElement::ONE)?;
    for i in 0..ntuples {
        let result = dotproduct_with_public::<B>(
            backend,
            &ys[i * tuple_size..(i + 1) * tuple_size],
            &challenges,
        )?;
        let tmp = backend.add_constant(&result, challenge * minus_one)?;
        y = backend.mul(&y, &tmp)?;
    }
    let z = backend.sub(&x, &y)?;
    backend.assert_zero(&z)
}

pub(crate) fn permutation_check_binary<M: Mac<Value = F2>, B: BackendLiftT<Wire = M>>(
    backend: &mut B::LiftedBackend,
    xs: &[B::Wire],
    ys: &[B::Wire],
    ntuples: usize,
    tuple_size: usize,
) -> Result<()>
where
    M::Value: IsSubFieldOf<M::Tag>,
{
    let xs: Vec<_> = xs
        .iter()
        .map(|x| {
            let mut array: Arr<M, DegreeModulo<F2, M::Tag>> = GenericArray::default();
            array[0] = *x;
            M::lift(&array)
        })
        .collect();
    let ys: Vec<_> = ys
        .iter()
        .map(|y| {
            let mut array: Arr<M, DegreeModulo<F2, M::Tag>> = GenericArray::default();
            array[0] = *y;
            M::lift(&array)
        })
        .collect();
    permutation_check(backend, &xs, &ys, ntuples, tuple_size)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    use ocelot::svole::{LPN_EXTEND_SMALL, LPN_SETUP_SMALL};
    use rand::{seq::SliceRandom, Rng};
    use scuttlebutt::{AesRng, Channel};
    use swanky_field::{FiniteField, FiniteRing};
    use swanky_field_binary::{F40b, F2};
    use swanky_field_f61p::F61p;

    use crate::{
        backend_extfield::{DietMacAndCheeseExtFieldProver, DietMacAndCheeseExtFieldVerifier},
        backend_trait::BackendT,
        mac::{MacProver, MacVerifier},
        svole_trait::{SvoleReceiver, SvoleSender},
        DietMacAndCheeseProver, DietMacAndCheeseVerifier,
    };

    use super::{permutation_check, permutation_check_binary};

    fn test_permutation<F: FiniteField>(ntuples: usize, tuple_size: usize, is_good: bool) {
        let mut rng = AesRng::new();
        let mut values: Vec<Vec<F>> = (0..ntuples)
            .map(|_| (0..tuple_size).map(|_| F::random(&mut rng)).collect())
            .collect();
        let xs: Vec<F> = values.clone().into_iter().flatten().collect();
        values.shuffle(&mut rng);
        let mut ys: Vec<F> = values.clone().into_iter().flatten().collect();
        if !is_good {
            let i = rng.gen_range(0..ys.len());
            ys[i] += F::ONE;
        }

        let xs_ = xs.clone();
        let ys_ = ys.clone();

        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let rng = AesRng::new();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let mut channel = Channel::new(reader, writer);

            let mut party = DietMacAndCheeseProver::<F, F, _, SvoleSender<F>>::init(
                &mut channel,
                rng,
                LPN_SETUP_SMALL,
                LPN_EXTEND_SMALL,
                false,
            )
            .unwrap();
            let xs: Vec<MacProver<F, F>> = xs_
                .into_iter()
                .map(|x| party.input_private(Some(x)).unwrap())
                .collect();
            let ys: Vec<MacProver<F, F>> = ys_
                .into_iter()
                .map(|y| party.input_private(Some(y)).unwrap())
                .collect();

            permutation_check(&mut party, &xs, &ys, ntuples, tuple_size).unwrap();
            if is_good {
                let _ = party.finalize().unwrap();
            } else {
                let _ = party.finalize().unwrap_err();
            }
        });

        let rng = AesRng::new();
        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let mut channel = Channel::new(reader, writer);

        let mut party = DietMacAndCheeseVerifier::<F, F, _, SvoleReceiver<F, F>>::init(
            &mut channel,
            rng,
            LPN_SETUP_SMALL,
            LPN_EXTEND_SMALL,
            false,
        )
        .unwrap();
        let xs: Vec<MacVerifier<F, F>> = xs
            .clone()
            .iter()
            .map(|_| party.input_private(None).unwrap())
            .collect();
        let ys: Vec<MacVerifier<F, F>> = ys
            .iter()
            .map(|_| party.input_private(None).unwrap())
            .collect();

        permutation_check(&mut party, &xs, &ys, ntuples, tuple_size).unwrap();
        if is_good {
            let _ = party.finalize().unwrap();
        } else {
            let _ = party.finalize().unwrap_err();
        }

        handle.join().unwrap();
    }

    fn test_permutation_binary(ntuples: usize, tuple_size: usize, is_good: bool) {
        let mut rng = AesRng::new();
        let mut values: Vec<Vec<F2>> = (0..ntuples)
            .map(|_| (0..tuple_size).map(|_| F2::random(&mut rng)).collect())
            .collect();
        let xs: Vec<F2> = values.clone().into_iter().flatten().collect();
        values.shuffle(&mut rng);
        let mut ys: Vec<F2> = values.clone().into_iter().flatten().collect();
        if !is_good {
            ys[0] += F2::ONE;
        }

        let xs_ = xs.clone();
        let ys_ = ys.clone();

        let (sender, receiver) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let rng = AesRng::new();
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
            let mut party2 = party
                .lift::<SvoleSender<F40b>>(LPN_SETUP_SMALL, LPN_EXTEND_SMALL)
                .unwrap();
            let xs: Vec<MacProver<F2, F40b>> = xs_
                .into_iter()
                .map(|x| party.input_private(Some(x)).unwrap())
                .collect();
            let ys: Vec<MacProver<F2, F40b>> = ys_
                .into_iter()
                .map(|y| party.input_private(Some(y)).unwrap())
                .collect();

            permutation_check_binary::<
                MacProver<F2, F40b>,
                DietMacAndCheeseExtFieldProver<
                    F40b,
                    Channel<BufReader<UnixStream>, BufWriter<UnixStream>>,
                    SvoleSender<F40b>,
                    SvoleSender<F40b>,
                >,
            >(&mut party2, &xs, &ys, ntuples, tuple_size)
            .unwrap();
            if is_good {
                let _ = party.finalize().unwrap();
                let _ = party2.finalize().unwrap();
            } else {
                let _ = party.finalize().unwrap();
                let _ = party2.finalize().unwrap_err();
            }
        });

        let rng = AesRng::new();
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
        let mut party2 = party
            .lift::<SvoleReceiver<F40b, F40b>>(LPN_SETUP_SMALL, LPN_EXTEND_SMALL)
            .unwrap();
        let xs: Vec<MacVerifier<F2, F40b>> = xs
            .clone()
            .iter()
            .map(|_| party.input_private(None).unwrap())
            .collect();
        let ys: Vec<MacVerifier<F2, F40b>> = ys
            .iter()
            .map(|_| party.input_private(None).unwrap())
            .collect();

        permutation_check_binary::<
            MacVerifier<F2, F40b>,
            DietMacAndCheeseExtFieldVerifier<
                F40b,
                Channel<BufReader<UnixStream>, BufWriter<UnixStream>>,
                SvoleReceiver<F40b, F40b>,
            >,
        >(&mut party2, &xs, &ys, ntuples, tuple_size)
        .unwrap();
        if is_good {
            let _ = party.finalize().unwrap();
            let _ = party2.finalize().unwrap();
        } else {
            let _ = party.finalize().unwrap();
            let _ = party2.finalize().unwrap_err();
        }

        handle.join().unwrap();
    }

    fn test_permutation_(ntuples: usize, tuple_size: usize, is_good: bool) {
        test_permutation::<F61p>(ntuples, tuple_size, is_good);
        test_permutation::<F40b>(ntuples, tuple_size, is_good);
        test_permutation_binary(ntuples, tuple_size, is_good);
    }

    #[test]
    fn permutation_of_one_element_works() {
        test_permutation_(1, 1, true);
    }

    #[test]
    fn bad_permutation_of_one_element_fails() {
        test_permutation_(1, 1, false);
    }

    #[test]
    fn permutation_of_ten_elements_works() {
        test_permutation_(10, 1, true);
    }

    #[test]
    fn bad_permutation_of_ten_elements_fails() {
        test_permutation_(10, 1, false);
    }

    #[test]
    fn permutation_of_ten_tuples_of_length_five_works() {
        test_permutation_(10, 5, true);
    }

    #[test]
    fn bad_permutation_of_ten_tuples_of_length_five_fails() {
        test_permutation_(10, 5, false);
    }
}
