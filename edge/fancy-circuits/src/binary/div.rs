use crate::{
    BinaryBundle,
    binary::{BinaryAddition, Constant, LeftShiftPad, Mux, TwosComplement},
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;

/// For [`BinaryBundle`]s `x` and `y`, output `x / y`, or zero if `y = 0`.
#[derive(Default)]
pub struct Div<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F> for Div<'a, N>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item, N>, &'a BinaryBundle<F::Item, N>);
    type Output = BinaryBundle<F::Item, N>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (xs, ys) = inputs;

        let ys_neg = TwosComplement::default().execute(backend, ys, channel)?;
        let mut acc = Constant::<N>::new(0).execute(backend, (), channel)?;
        let mut qs = Constant::<N>::new(0).execute(backend, (), channel)?;
        for (i, x) in xs.wires().iter().rev().enumerate() {
            acc = LeftShiftPad::default().execute(backend, (&acc, 1, x), channel)?;
            let (res, cout) =
                BinaryAddition::default().execute(backend, (&acc, &ys_neg), channel)?;
            acc = Mux::default().execute(backend, (cout.clone(), &acc, &res), channel)?;
            qs.set(cout, i);
        }
        qs.reverse(); // Switch back to little-endian
        Ok(qs)
    }
}

#[cfg(test)]
mod test {
    use crate::{BinaryBundle, binary::Div};
    use fancy_plaintext::Dummy;
    use rand::{RngExt, rng};

    #[test]
    fn div_circuit_works() {
        const N: usize = 64;
        const Q: u128 = 1 << N;

        let mut rng = rng();
        let circuit = Div::<N>::default();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let mut y = rng.random::<u128>() % Q;
            while y == 0 {
                y = rng.random::<u128>() % Q;
            }
            let x_input = BinaryBundle::from(x);
            let y_input = BinaryBundle::from(y);
            let output = Dummy::eval(&circuit, (&x_input, &y_input)).unwrap();
            assert_eq!(Into::<u128>::into(output), x / y);
        }

        // Ensure that division by zero equals zero.
        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let x_input = BinaryBundle::from(x);
            let y_input = BinaryBundle::from(0);
            let output = Dummy::eval(&circuit, (&x_input, &y_input)).unwrap();
            assert_eq!(Into::<u128>::into(output), 0);
        }
    }
}
