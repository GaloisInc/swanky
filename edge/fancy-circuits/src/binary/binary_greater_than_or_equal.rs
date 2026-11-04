use crate::{BinaryBundle, binary::BinaryLessThan};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;

/// Binary greater than or equal.
///
/// For [`BinaryBundle`]s `x` and `y`, return `x >= y`.
#[derive(Default)]
pub struct BinaryGreaterThanOrEqual<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, const N: usize> BinaryGreaterThanOrEqual<'a, N> {
    /// Create a new [`BinaryGreaterThanOrEqual`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F>
    for BinaryGreaterThanOrEqual<'a, N>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item, N>, &'a BinaryBundle<F::Item, N>);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let z = BinaryLessThan::new().execute(backend, inputs, channel)?;
        Ok(backend.negate(&z))
    }
}

pub mod test {
    use super::*;
    use fancy_traits::CircuitInputMapper;

    /// Circuit for testing [`BinaryGreaterThanOrEqual`].
    pub struct TestBinaryGreaterThanOrEqual<const N: usize>;
    impl<F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F>
        for TestBinaryGreaterThanOrEqual<N>
    {
        type Input = (BinaryBundle<F::Item, N>, BinaryBundle<F::Item, N>);
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            BinaryGreaterThanOrEqual::new().execute(backend, (&inputs.0, &inputs.1), channel)
        }
    }

    impl<F: FancyBinary + FancyConstant<F2>, const N: usize> CircuitInputMapper<F>
        for TestBinaryGreaterThanOrEqual<N>
    {
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

    #[test]
    fn binary_greater_than_or_equal() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        const N: usize = 64;
        const Q: u128 = 1 << N;

        let mut rng = rand::rng();
        let circuit = TestBinaryGreaterThanOrEqual::<N>;

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let y = rng.random::<u128>() % Q;
            let x_input = BinaryBundle::<_, N>::from(x);
            let y_input = BinaryBundle::<_, N>::from(y);
            let output = Dummy::eval(&circuit, (x_input, y_input)).unwrap();
            assert_eq!(output.val(), F2::from(x >= y));
        }
    }
}
