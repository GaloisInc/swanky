use std::{iter::Peekable, marker::PhantomData};

use crate::{
    backend_multifield::BackendLiftT, backend_trait::BackendT,
    gadgets::dotproduct_with_public_powers, mac::Mac,
};
use eyre::{ensure, Result};
use generic_array::{typenum::Unsigned, GenericArray};
use scuttlebutt::generic_array_length::Arr;
use swanky_field::{DegreeModulo, FiniteField, FiniteRing};

/// A permutation check gadget that asserts that `xs = 𝛑(ys)`, erroring out if
/// not.
///
/// This gadget currently only works over fields larger than the statistical
/// security parameter (which we have harded at 40 bits).
///
/// **Note!** This gadget _assumes_ that the lengths of `xs` and `ys` are equal,
/// and that the length of each equals `ntuples * tuple_size`!
pub(crate) fn permutation_check<B: BackendT>(
    backend: &mut B,
    mut xs: impl Iterator<Item = B::Wire>,
    mut ys: impl Iterator<Item = B::Wire>,
    ntuples: usize,
    tuple_size: usize,
) -> Result<()> {
    ensure!(
        <B::FieldElement as FiniteField>::NumberOfBitsInBitDecomposition::USIZE >= 40,
        "Field size must be >= 40 bits"
    );

    // ensure!(
    //     xs.len() == ys.len(),
    //     "Input lengths are not equal: {} != {}",
    //     xs.len(),
    //     ys.len()
    // );
    // ensure!(
    //     xs.len() == ntuples * tuple_size,
    //     "Provided input length not equal to expected input length: {} != {}",
    //     xs.len(),
    //     ntuples * tuple_size,
    // );

    let minus_one = -B::FieldElement::ONE;
    let random = backend.random()?;
    let challenge = backend.random()?;

    let mut x = backend.constant(B::FieldElement::ONE)?;
    for _ in 0..ntuples {
        let result = dotproduct_with_public_powers::<B>(backend, &mut xs, random, tuple_size)?;
        let tmp = backend.add_constant(&result, challenge * minus_one)?;
        x = backend.mul(&x, &tmp)?;
    }
    let mut y = backend.constant(B::FieldElement::ONE)?;
    for _ in 0..ntuples {
        let result = dotproduct_with_public_powers::<B>(backend, &mut ys, random, tuple_size)?;
        let tmp = backend.add_constant(&result, challenge * minus_one)?;
        y = backend.mul(&y, &tmp)?;
    }
    let z = backend.sub(&x, &y)?;
    backend.assert_zero(&z)
}

/// This type implements an iterator for packing elements together based on a
/// given tuple size.
struct Packer<M: Mac, B: BackendLiftT<Wire = M>, I: Iterator<Item = B::Wire>> {
    xs: Peekable<I>,
    tuple_size: usize,
    array: Arr<M, DegreeModulo<M::Value, M::Tag>>,
    nbits: usize,
    nbits_count: usize,
    tuple_count: usize,
    _phantom: PhantomData<(M, B)>,
}

impl<M: Mac, B: BackendLiftT<Wire = M>, I: Iterator<Item = B::Wire>> Packer<M, B, I> {
    /// Create a new [`Packer`] from an iterator and a given `tuple_size`.
    pub fn new(xs: I, tuple_size: usize) -> Self {
        Self {
            xs: xs.peekable(),
            tuple_size,
            array: GenericArray::default(),
            nbits: <M::Tag as FiniteField>::NumberOfBitsInBitDecomposition::USIZE,
            nbits_count: 0,
            tuple_count: 0,
            _phantom: PhantomData,
        }
    }
}

impl<M: Mac, B: BackendLiftT<Wire = M>, I: Iterator<Item = B::Wire>> Iterator for Packer<M, B, I> {
    type Item = <M as Mac>::LiftedMac;

    fn next(&mut self) -> Option<Self::Item> {
        for x in &mut self.xs {
            self.array[self.nbits_count] = x;
            self.nbits_count += 1;
            self.tuple_count += 1;
            // There are three conditions in which we push a packed element:
            // 1. We are out of space in the superfield (i.e., `nbits_count == nbits`)
            // 2. We are out of space in the tuple itself (i.e., `tuple_count == tuple_size`)
            if self.nbits_count == self.nbits || self.tuple_count == self.tuple_size {
                let elem = M::lift(&self.array);
                self.array = GenericArray::default();
                self.nbits_count = 0;
                // Only reset `tuple_count` if we've hit `tuple_size`.
                if self.tuple_count == self.tuple_size {
                    self.tuple_count = 0;
                }
                return Some(elem);
            }
        }
        // 3. We are out of elements in general
        if self.nbits_count > 0 {
            let elem = M::lift(&self.array);
            self.nbits_count = 0;
            return Some(elem);
        }
        None
    }
}

/// A permutation check gadget, designed for binary fields, that asserts that
/// `xs = 𝛑(ys)`, erroring out if not.
///
/// **Note!** _Only_ use this circuit on binary values. There is no guarantee
/// it'll work for non-binary values!
pub(crate) fn permutation_check_binary<M: Mac, B: BackendLiftT<Wire = M>>(
    backend: &mut B::LiftedBackend,
    xs: impl Iterator<Item = B::Wire>,
    ys: impl Iterator<Item = B::Wire>,
    ntuples: usize,
    tuple_size: usize,
) -> Result<()> {
    let nbits = <M::Tag as FiniteField>::NumberOfBitsInBitDecomposition::USIZE;
    let new_tuple_size = (tuple_size + nbits - 1) / nbits;
    let packed_xs = Packer::<M, B, _>::new(xs, tuple_size);
    let packed_ys = Packer::<M, B, _>::new(ys, tuple_size);
    permutation_check::<B::LiftedBackend>(backend, packed_xs, packed_ys, ntuples, new_tuple_size)
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

            permutation_check(
                &mut party,
                xs.into_iter(),
                ys.into_iter(),
                ntuples,
                tuple_size,
            )
            .unwrap();
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

        permutation_check(
            &mut party,
            xs.into_iter(),
            ys.into_iter(),
            ntuples,
            tuple_size,
        )
        .unwrap();
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
            >(
                &mut party2,
                xs.into_iter(),
                ys.into_iter(),
                ntuples,
                tuple_size,
            )
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
                SvoleReceiver<F2, F40b>,
                SvoleReceiver<F40b, F40b>,
            >,
        >(
            &mut party2,
            xs.into_iter(),
            ys.into_iter(),
            ntuples,
            tuple_size,
        )
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
        test_permutation_binary(ntuples, tuple_size, is_good);
    }

    macro_rules! permutation_tester {
        ( $mod: ident, $ntuples: literal, $tuple_size: literal ) => {
            mod $mod {
                #[test]
                fn permutation_works() {
                    super::test_permutation_($ntuples, $tuple_size, true);
                }

                #[test]
                fn bad_permutation_fails() {
                    super::test_permutation_($ntuples, $tuple_size, false);
                }
            }
        };
    }

    permutation_tester!(permutation_1_1, 1, 1);
    permutation_tester!(permutation_10_1, 10, 1);
    permutation_tester!(permutation_10_5, 10, 5);
    permutation_tester!(permutation_1_40, 1, 40);
    permutation_tester!(permutation_1_41, 1, 41);
    permutation_tester!(permutation_101_41, 101, 41);
}
