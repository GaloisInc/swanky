use crate::{BinaryBundle, binary::BinaryLessThan};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary, FancyBinaryConstant};
use swanky_channel::Channel;
use swanky_error::Result;

/// Binary greater than or equal.
///
/// For [`BinaryBundle`]s `x` and `y`, return `x >= y`.
#[derive(Default)]
pub struct BinaryGreaterThanOrEqual<'a>(PhantomData<&'a ()>);

impl<'a> BinaryGreaterThanOrEqual<'a> {
    /// Create a new [`BinaryGreaterThanOrEqual`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary + FancyBinaryConstant> Circuit<F> for BinaryGreaterThanOrEqual<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, &'a BinaryBundle<F::Item>);
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
    pub struct TestBinaryGreaterThanOrEqual(pub usize);
    impl<F: FancyBinary + FancyBinaryConstant> Circuit<F> for TestBinaryGreaterThanOrEqual {
        type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
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

    impl<F: FancyBinary + FancyBinaryConstant> CircuitInputMapper<F> for TestBinaryGreaterThanOrEqual {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), self.0 * 2);
            let (x, y) = inputs.split_at(self.0);
            (BinaryBundle::new(x.to_vec()), BinaryBundle::new(y.to_vec()))
        }

        fn ninputs(&self) -> usize {
            self.0 * 2
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    #[test]
    fn binary_greater_than_or_equal() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        let mut rng = rand::rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = TestBinaryGreaterThanOrEqual(nbits);

        for _ in 0..16 {
            let x = rng.random::<u128>() % q;
            let y = rng.random::<u128>() % q;
            let x_input = BinaryBundle::from((x, nbits));
            let y_input = BinaryBundle::from((y, nbits));
            let output = Dummy::eval(&c, (x_input, y_input)).unwrap();
            assert_eq!(output.val() > 0, x >= y);
        }
    }
}
