use crate::{
    BinaryBundle,
    binary::{Mux, MuxConstants},
    util::u128_to_bits,
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary, FancyBinaryConstant};
use swanky_channel::Channel;
use swanky_error::Result;

/// For bit `b` and [`BinaryBundle`]s `x` and `y`, output `x` if `b == 0`, and
/// `y` otherwise.
#[derive(Default)]
pub struct BinaryMultiplex<'a>(PhantomData<&'a ()>);

impl<'a> BinaryMultiplex<'a> {
    /// Create a new [`BinaryMultiplex`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary> Circuit<F> for BinaryMultiplex<'a>
where
    F::Item: 'a,
{
    type Input = (
        F::Item,
        &'a BinaryBundle<F::Item>,
        &'a BinaryBundle<F::Item>,
    );
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (b, xs, ys) = inputs;
        xs.wires()
            .iter()
            .zip(ys.wires().iter())
            .map(|(x, y)| Mux::new().execute(backend, (&b.clone(), x, y), channel))
            .collect::<Result<Vec<_>>>()
            .map(BinaryBundle::new)
    }
}

/// For bit `b` and constants `c1` and `c2` of bitlength `n`, output `c1` if `b
/// == 0` and `c2` otherwise.
pub struct BinaryMultiplexConstantBits;

impl<F: FancyBinary + FancyBinaryConstant> Circuit<F> for BinaryMultiplexConstantBits {
    type Input = (F::Item, u128, u128, usize);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (b, c1, c2, nbits) = inputs;

        let c1_bs = u128_to_bits(c1, nbits)
            .into_iter()
            .map(|x: u16| x > 0)
            .collect::<Vec<_>>();
        let c2_bs = u128_to_bits(c2, nbits)
            .into_iter()
            .map(|x: u16| x > 0)
            .collect::<Vec<_>>();
        c1_bs
            .into_iter()
            .zip(c2_bs)
            .map(|(b1, b2)| MuxConstants::new().execute(backend, (&b.clone(), b1, b2), channel))
            .collect::<Result<_>>()
            .map(BinaryBundle::new)
    }
}

#[cfg(test)]
mod test {
    use super::BinaryMultiplex;
    use crate::{BinaryBundle, binary::BinaryMultiplexConstantBits};
    use fancy_plaintext::{Dummy, DummyVal};
    use rand::RngExt;

    #[test]
    fn binary_multiplex() {
        let mut rng = rand::rng();
        let nbits = 1 + (rng.random_range(..200usize));
        let x = rng.random::<u128>() % (nbits as u128);
        let y = rng.random::<u128>() % (nbits as u128);
        let x_inputs = BinaryBundle::from((x, nbits));
        let y_inputs = BinaryBundle::from((y, nbits));

        for b in 0..=1 {
            let output = Dummy::eval(
                &BinaryMultiplex::new(),
                (DummyVal::new(b, 2), &x_inputs, &y_inputs),
            )
            .unwrap();
            assert_eq!(Into::<u128>::into(output), if b == 0 { x } else { y });
        }
    }

    #[test]
    fn binary_multiplex_constant_bits() {
        let mut rng = rand::rng();
        let nbits = 1 + (rng.random_range(..200usize));
        let x = rng.random::<u128>() % (nbits as u128);
        let y = rng.random::<u128>() % (nbits as u128);

        for b in 0..=1 {
            let output = Dummy::eval(
                &BinaryMultiplexConstantBits,
                (DummyVal::new(b, 2), x, y, nbits),
            )
            .unwrap();
            assert_eq!(Into::<u128>::into(output), if b == 0 { x } else { y });
        }
    }
}
