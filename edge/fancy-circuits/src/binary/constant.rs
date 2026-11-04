use crate::{BinaryBundle, util::u128_to_bits};
use fancy_traits::{Circuit, Fancy, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;

/// Binary constant.
///
/// On input `x`, return a [`BinaryBundle`] containing `x % 2^N`, where `N` is
/// the length of the [`BinaryBundle`].
pub struct Constant<const N: usize>(u128);

impl<const N: usize> Constant<N> {
    /// Create a new [`BinaryConstant`] circuit for `x % 2^N`.
    pub fn new(x: u128) -> Self {
        Self(x)
    }
}

impl<F: FancyConstant<F2>, const N: usize> Circuit<F> for Constant<N> {
    type Input = ();
    type Output = BinaryBundle<F::Item, N>;

    fn execute(&self, backend: &mut F, _: Self::Input, _: &mut Channel) -> Result<Self::Output> {
        let xs = u128_to_bits::<N>(self.0);
        Ok(BinaryBundle::new(xs.map(|x| backend.constant(x))))
    }
}

pub mod test {
    use super::*;
    use fancy_traits::CircuitInputMapper;

    /// Circuit for testing [`Constant`].
    pub struct TestConstant<const N: usize>(pub u128);
    impl<F: FancyConstant<F2>, const N: usize> Circuit<F> for TestConstant<N> {
        type Input = <Constant<N> as Circuit<F>>::Input;
        type Output = <Constant<N> as Circuit<F>>::Output;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut swanky_channel::Channel,
        ) -> Result<Self::Output> {
            Constant::new(self.0).execute(backend, inputs, channel)
        }
    }

    impl<F: FancyConstant<F2>, const N: usize> CircuitInputMapper<F> for TestConstant<N> {
        fn map(&self, inputs: Vec<<F as Fancy>::Item>) -> Self::Input {
            assert!(inputs.is_empty());
        }

        fn ninputs(&self) -> usize {
            0
        }
    }

    #[test]
    fn constant_circuit_works() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        const N: usize = 64;
        const Q: u128 = 1 << N;

        let mut rng = rand::rng();
        for _ in 0..16 {
            let value = rng.random::<u128>() % Q;
            let circuit = TestConstant::<N>(value);
            let output = Dummy::eval(&circuit, ()).unwrap();
            assert_eq!(Into::<u128>::into(output), value);
        }
    }
}
