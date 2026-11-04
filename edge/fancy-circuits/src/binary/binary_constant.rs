use crate::{BinaryBundle, util::u128_to_bits};
use fancy_traits::{Circuit, Fancy, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;

/// Binary constant.
///
/// For `(value, nbits)`, return a [`BinaryBundle`] containing `value` in its
/// bit representation.
pub struct BinaryConstant<const N: usize>(u128);

impl<const N: usize> BinaryConstant<N> {
    /// Create a new [`BinaryConstant`] circuit for `value % 2^N`.
    pub fn new(value: u128) -> Self {
        Self(value)
    }
}

impl<F: FancyConstant<F2>, const N: usize> Circuit<F> for BinaryConstant<N> {
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

    /// Circuit for testing [`BinaryConstant`].
    pub struct TestBinaryConstant<const N: usize>(pub u128);
    impl<F: FancyConstant<F2>, const N: usize> Circuit<F> for TestBinaryConstant<N> {
        type Input = <BinaryConstant<N> as Circuit<F>>::Input;
        type Output = <BinaryConstant<N> as Circuit<F>>::Output;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut swanky_channel::Channel,
        ) -> Result<Self::Output> {
            BinaryConstant::new(self.0).execute(backend, inputs, channel)
        }
    }

    impl<F: FancyConstant<F2>, const N: usize> CircuitInputMapper<F> for TestBinaryConstant<N> {
        fn map(&self, inputs: Vec<<F as Fancy>::Item>) -> Self::Input {
            assert!(inputs.is_empty());
        }

        fn ninputs(&self) -> usize {
            0
        }
    }

    #[test]
    fn binary_constant() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        let mut rng = rand::rng();
        const N: usize = 127;
        for _ in 0..16 {
            let value = rng.random::<u128>() % (N as u128);
            let c = TestBinaryConstant::<N>(value);
            let output = Dummy::eval(&c, ()).unwrap();
            assert_eq!(Into::<u128>::into(output), value);
        }
    }
}
