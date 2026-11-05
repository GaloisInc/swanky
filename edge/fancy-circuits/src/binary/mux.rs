use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;

use crate::{BinaryBundle, util::u128_to_bits};

/// For input `(b, x, y)` return `x` if `b == 0`, otherwise return `y`.
#[derive(Default)]
pub struct MuxBit<'a>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary> Circuit<F> for MuxBit<'a>
where
    F::Item: 'a,
{
    type Input = (&'a F::Item, &'a F::Item, &'a F::Item);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        // The mux can be computed as `b (x ^ y) ^ x`.
        let (b, x, y) = inputs;
        let xor = backend.xor(x, y);
        let and = backend.and(b, &xor, channel)?;
        Ok(backend.xor(&and, x))
    }
}

/// For input `(b, c1, c2)`, return `c1` if `b == 0`, otherwise return `c2`.
///
/// This circuit requires no communication.
#[derive(Default)]
pub struct MuxBitConstants<'a>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>> Circuit<F> for MuxBitConstants<'a>
where
    F::Item: 'a,
{
    type Input = (&'a F::Item, F2, F2);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        _: &mut Channel,
    ) -> Result<Self::Output> {
        let (b, c1, c2) = inputs;
        Ok(match (c1.into(), c2.into()) {
            (false, true) => b.clone(),
            (true, false) => backend.negate(b),
            (false, false) => backend.constant(F2::ZERO),
            (true, true) => backend.constant(F2::ONE),
        })
    }
}

/// For bit `b` and [`BinaryBundle`]s `x` and `y`, output `x` if `b == 0`, and
/// `y` otherwise.
#[derive(Default)]
pub struct Mux<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary, const N: usize> Circuit<F> for Mux<'a, N>
where
    F::Item: 'a,
{
    type Input = (
        F::Item,
        &'a BinaryBundle<F::Item, N>,
        &'a BinaryBundle<F::Item, N>,
    );
    type Output = BinaryBundle<F::Item, N>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (b, xs, ys) = inputs;
        let res: [_; N] = xs
            .wires()
            .iter()
            .zip(ys.wires().iter())
            .map(|(x, y)| MuxBit::default().execute(backend, (&b.clone(), x, y), channel))
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .expect("vector should be of length `N`");
        Ok(BinaryBundle::new(res))
    }
}

/// For bit `b` and constants `c1` and `c2`, output `c1` if `b == 0` and `c2`
/// otherwise.
///
/// This circuit requires no communication.
#[derive(Default)]
pub struct MuxConstants<const N: usize>;

impl<F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F> for MuxConstants<N> {
    type Input = (F::Item, u128, u128);
    type Output = BinaryBundle<F::Item, N>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (b, c1, c2) = inputs;

        let c1_bs = u128_to_bits::<N>(c1);
        let c2_bs = u128_to_bits::<N>(c2);
        let res = c1_bs
            .into_iter()
            .zip(c2_bs)
            .map(|(b1, b2)| {
                MuxBitConstants::default().execute(backend, (&b.clone(), b1, b2), channel)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(BinaryBundle::new(
            res.try_into().expect("vector should be of length `N`"),
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        BinaryBundle,
        binary::mux::{Mux, MuxBitConstants},
    };
    use fancy_plaintext::{Dummy, DummyVal};
    use rand::RngExt;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;

    #[test]
    fn mux_bit_circuit_works() {
        let circuit = MuxBit::default();

        for b in [F2::ZERO, F2::ONE] {
            for x in [F2::ZERO, F2::ONE] {
                for y in [F2::ZERO, F2::ONE] {
                    let b_val = DummyVal::new(b);
                    let x_val = DummyVal::new(x);
                    let y_val = DummyVal::new(y);
                    let output = Dummy::eval(&circuit, (&b_val, &x_val, &y_val)).unwrap();
                    assert_eq!(output.val(), if b == F2::ZERO { x } else { y });
                }
            }
        }
    }

    #[test]
    fn mux_bit_constants_circuit_works() {
        let circuit = MuxBitConstants::default();

        for b in [F2::ZERO, F2::ONE] {
            for x in [F2::ZERO, F2::ONE] {
                for y in [F2::ZERO, F2::ONE] {
                    let b_val = DummyVal::new(b);
                    let output = Dummy::eval(&circuit, (&b_val, x, y)).unwrap();
                    assert_eq!(output.val(), if b == F2::ZERO { x } else { y });
                }
            }
        }
    }

    #[test]
    fn mux_circuit_works() {
        const N: usize = 64;
        let circuit = Mux::<N>::default();

        let mut rng = rand::rng();
        let x = rng.random::<u128>() % (N as u128);
        let y = rng.random::<u128>() % (N as u128);
        let x_inputs = BinaryBundle::from(x);
        let y_inputs = BinaryBundle::from(y);

        for b in [F2::ZERO, F2::ONE] {
            let output = Dummy::eval(&circuit, (DummyVal::new(b), &x_inputs, &y_inputs)).unwrap();
            assert_eq!(
                Into::<u128>::into(output),
                if b == F2::ZERO { x } else { y }
            );
        }
    }

    #[test]
    fn mux_constants_circuit_works() {
        const N: usize = 64;
        let circuit = MuxConstants::<N>;

        let mut rng = rand::rng();
        let x = rng.random::<u128>() % (N as u128);
        let y = rng.random::<u128>() % (N as u128);

        for b in [F2::ZERO, F2::ONE] {
            let output = Dummy::eval(&circuit, (DummyVal::new(b), x, y)).unwrap();
            assert_eq!(
                Into::<u128>::into(output),
                if b == F2::ZERO { x } else { y }
            );
        }
    }
}
