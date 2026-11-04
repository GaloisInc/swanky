use crate::{BinaryBundle, binary::AndMany};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary};
use swanky_channel::Channel;
use swanky_error::Result;

/// Binary equality.
///
/// For [`BinaryBundle`]s `x` and `y`, return `x == y`.
#[derive(Default)]
pub struct BinaryEquality<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary, const N: usize> Circuit<F> for BinaryEquality<'a, N>
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
        let (x, y) = inputs;

        let zs = x
            .wires()
            .iter()
            .zip(y.wires().iter())
            .map(|(x, y)| {
                let xy = backend.xor(x, y);
                backend.negate(&xy)
            })
            .collect::<Vec<_>>();

        // If any negated XOR is 0, then the values are not equal
        AndMany::default().execute(backend, zs.as_slice(), channel)
    }
}

pub mod test {
    use super::*;
    use fancy_traits::CircuitInputMapper;
    #[cfg(test)]
    use swanky_field::FiniteRing;
    #[cfg(test)]
    use swanky_field_binary::F2;

    /// Circuit for testing [`BinaryEquality`].
    pub struct TestBinaryEquality<const N: usize>;
    impl<F: FancyBinary, const N: usize> Circuit<F> for TestBinaryEquality<N> {
        type Input = (BinaryBundle<F::Item, N>, BinaryBundle<F::Item, N>);
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            BinaryEquality::default().execute(backend, (&inputs.0, &inputs.1), channel)
        }
    }

    impl<F: FancyBinary, const N: usize> CircuitInputMapper<F> for TestBinaryEquality<N> {
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
    fn binary_equality() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        const N: usize = 64;
        const Q: u128 = 1 << 64;

        let mut rng = rand::rng();
        let circuit = TestBinaryEquality::<N>;

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let y = rng.random::<u128>() % Q;
            let x_input = BinaryBundle::<_, N>::from(x);
            let y_input = BinaryBundle::<_, N>::from(y);
            let output = Dummy::eval(&circuit, (x_input, y_input)).unwrap();
            assert_eq!(output.val(), F2::from(x == y));
        }

        // Test specifically for equal values
        for _ in 0..8 {
            let x = rng.random::<u128>() % Q;
            let x_input = BinaryBundle::<_, N>::from(x);
            let output = Dummy::eval(&circuit, (x_input.clone(), x_input)).unwrap();
            assert_eq!(output.val(), F2::ONE);
        }
    }
}
