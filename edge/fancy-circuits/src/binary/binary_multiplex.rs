use crate::{
    BinaryBundle,
    binary::{Mux, MuxConstants},
    util::u128_to_bits,
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;

/// For bit `b` and [`BinaryBundle`]s `x` and `y`, output `x` if `b == 0`, and
/// `y` otherwise.
#[derive(Default)]
pub struct BinaryMultiplex<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, const N: usize> BinaryMultiplex<'a, N> {
    /// Create a new [`BinaryMultiplex`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary, const N: usize> Circuit<F> for BinaryMultiplex<'a, N>
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
            .map(|(x, y)| Mux::new().execute(backend, (&b.clone(), x, y), channel))
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .expect("vector should be of length `N`");
        Ok(BinaryBundle::new(res))
    }
}

/// For bit `b` and constants `c1` and `c2` of bitlength `n`, output `c1` if `b
/// == 0` and `c2` otherwise.
pub struct BinaryMultiplexConstantBits<const N: usize>;

impl<F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F>
    for BinaryMultiplexConstantBits<N>
{
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
            .map(|(b1, b2)| MuxConstants::new().execute(backend, (&b.clone(), b1, b2), channel))
            .collect::<Result<Vec<_>>>()?;
        Ok(BinaryBundle::new(
            res.try_into().expect("vector should be of length `N`"),
        ))
    }
}

#[cfg(test)]
mod test {
    use super::BinaryMultiplex;
    use crate::{BinaryBundle, binary::BinaryMultiplexConstantBits};
    use fancy_plaintext::{Dummy, DummyVal};
    use rand::RngExt;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;

    #[test]
    fn binary_multiplex() {
        const N: usize = 64;

        let mut rng = rand::rng();
        let x = rng.random::<u128>() % (N as u128);
        let y = rng.random::<u128>() % (N as u128);
        let x_inputs = BinaryBundle::from(x);
        let y_inputs = BinaryBundle::from(y);

        for b in [F2::ZERO, F2::ONE] {
            let output = Dummy::eval(
                &BinaryMultiplex::<N>::default(),
                (DummyVal::new(b), &x_inputs, &y_inputs),
            )
            .unwrap();
            assert_eq!(
                Into::<u128>::into(output),
                if b == F2::ZERO { x } else { y }
            );
        }
    }

    #[test]
    fn binary_multiplex_constant_bits() {
        const N: usize = 64;

        let mut rng = rand::rng();
        let x = rng.random::<u128>() % (N as u128);
        let y = rng.random::<u128>() % (N as u128);

        for b in [F2::ZERO, F2::ONE] {
            let output =
                Dummy::eval(&BinaryMultiplexConstantBits::<N>, (DummyVal::new(b), x, y)).unwrap();
            assert_eq!(
                Into::<u128>::into(output),
                if b == F2::ZERO { x } else { y }
            );
        }
    }
}
