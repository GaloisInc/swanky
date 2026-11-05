use crate::{
    BinaryBundle,
    binary::{Add, TwosComplement},
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, CircuitInputMapper, CircuitOutputMapper, FancyBinary, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;

/// Binary subtract.
///
/// For [`BinaryBundle`]s `x` and `y`, return `(x - y, underflow)`, where
/// `underflow` indicates `y != 0 && x >= y`.
#[derive(Default)]
pub struct Sub<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F> for Sub<'a, N>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item, N>, &'a BinaryBundle<F::Item, N>);
    type Output = (BinaryBundle<F::Item, N>, F::Item);

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;

        let neg_y = TwosComplement::default().execute(backend, y, channel)?;
        Add::default().execute(backend, (x, &neg_y), channel)
    }
}

/// Circuit for testing [`Sub`].
pub struct TestSub<const N: usize>;
impl<F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F> for TestSub<N> {
    type Input = (BinaryBundle<F::Item, N>, BinaryBundle<F::Item, N>);
    type Output = (BinaryBundle<F::Item, N>, F::Item);

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        Sub::default().execute(backend, (&inputs.0, &inputs.1), channel)
    }
}

impl<F: FancyBinary + FancyConstant<F2>, const N: usize> CircuitInputMapper<F> for TestSub<N> {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), 2 * N);
        let (x, y) = inputs.split_at(N);
        (
            BinaryBundle::new(
                x.to_vec()
                    .try_into()
                    .expect("vector should be of length `N`"),
            ),
            BinaryBundle::new(
                y.to_vec()
                    .try_into()
                    .expect("vector should be of length `N`"),
            ),
        )
    }

    fn ninputs(&self) -> usize {
        2 * N
    }
}

impl<F: FancyBinary + FancyConstant<F2>, const N: usize> CircuitOutputMapper<F> for TestSub<N> {
    fn flatten(output: Self::Output) -> Vec<F::Item> {
        [output.0.wires().to_vec(), vec![output.1]].concat()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use fancy_plaintext::Dummy;
    use rand::RngExt;

    #[test]
    fn sub_circuit_works() {
        const N: usize = 64;
        const Q: u128 = 1 << N;

        let mut rng = rand::rng();
        let circuit = Sub::<N>::default();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let y = rng.random::<u128>() % Q;
            let x_input = BinaryBundle::from(x);
            let y_input = BinaryBundle::from(y);
            let outputs = Dummy::eval(&circuit, (&x_input, &y_input)).unwrap();
            assert_eq!(Into::<u128>::into(outputs.0), x.overflowing_sub(y).0 % Q);
            assert_eq!(outputs.1.val(), F2::from(y != 0 && x >= y));
        }
    }
}
