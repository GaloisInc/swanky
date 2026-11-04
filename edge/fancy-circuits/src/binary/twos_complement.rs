use crate::{
    BinaryBundle,
    binary::{BinaryAdditionNoCarry, Constant},
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, CircuitInputMapper, CircuitOutputMapper, FancyBinary, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;

/// On input [`BinaryBundle`] `x`, output the two's complement of `x`.
///
/// This is equivalent to computing `(!x) + 1` in Rust.
#[derive(Default)]
pub struct TwosComplement<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F> for TwosComplement<'a, N>
where
    F::Item: 'a,
{
    type Input = &'a BinaryBundle<F::Item, N>;
    type Output = BinaryBundle<F::Item, N>;

    fn execute(
        &self,
        backend: &mut F,
        input: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let not_xs = BinaryBundle::new(
            input
                .wires()
                .iter()
                .map(|x| backend.negate(x))
                .collect::<Vec<_>>()
                .try_into()
                .expect("vector should be of length `N`"),
        );
        let one = Constant::new(1).execute(backend, (), channel)?;
        BinaryAdditionNoCarry::default().execute(backend, (&not_xs, &one), channel)
    }
}

/// Circuit for testing [`TwosComplement`].
pub struct TestTwosComplement<const N: usize>;
impl<F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F> for TestTwosComplement<N> {
    type Input = BinaryBundle<F::Item, N>;
    type Output = BinaryBundle<F::Item, N>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        TwosComplement::default().execute(backend, &inputs, channel)
    }
}

impl<F: FancyBinary + FancyConstant<F2>, const N: usize> CircuitInputMapper<F>
    for TestTwosComplement<N>
{
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), N);
        BinaryBundle::new(inputs.try_into().expect("vector should be of length `N`"))
    }

    fn ninputs(&self) -> usize {
        N
    }
}

impl<F: FancyBinary + FancyConstant<F2>, const N: usize> CircuitOutputMapper<F>
    for TestTwosComplement<N>
{
    fn flatten(output: Self::Output) -> Vec<F::Item> {
        output.wires().to_vec()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use fancy_plaintext::Dummy;
    use rand::RngExt;

    #[test]
    fn twos_complement_circuit_works() {
        const N: usize = 64;
        const Q: u128 = 1 << N;

        let mut rng = rand::rng();
        let circuit = TwosComplement::<N>::default();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let x_input = BinaryBundle::from(x);
            let output = Dummy::eval(&circuit, &x_input).unwrap();
            assert_eq!(Into::<u128>::into(output), (((!x) % Q) + 1) % Q);
        }
    }
}
