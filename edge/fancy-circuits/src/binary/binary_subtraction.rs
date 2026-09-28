use crate::{
    BinaryBundle,
    binary::{BinaryAddition, BinaryTwosComplement},
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary, FancyBinaryConstant};
use swanky_channel::Channel;
use swanky_error::Result;

/// Binary subtract.
///
/// For [`BinaryBundle`]s `x` and `y`, return `(x - y, underflow)`, where
/// `underflow` indicates `y != 0 && x >= y`.
#[derive(Default)]
pub struct BinarySubtraction<'a>(PhantomData<&'a ()>);

impl<'a> BinarySubtraction<'a> {
    /// Create a new [`BinarySubtraction`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary + FancyBinaryConstant> Circuit<F> for BinarySubtraction<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, &'a BinaryBundle<F::Item>);
    type Output = (BinaryBundle<F::Item>, F::Item);

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        assert_eq!(x.len(), y.len());

        let neg_y = BinaryTwosComplement::new().execute(backend, y, channel)?;
        BinaryAddition::new().execute(backend, (x, &neg_y), channel)
    }
}

pub mod test {
    use super::*;
    use fancy_traits::{CircuitInputMapper, CircuitOutputMapper};

    /// Circuit for testing [`BinarySubtraction`].
    pub struct TestBinarySubtraction(pub usize);
    impl<F: FancyBinary + FancyBinaryConstant> Circuit<F> for TestBinarySubtraction {
        type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
        type Output = (BinaryBundle<F::Item>, F::Item);

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            BinarySubtraction::new().execute(backend, (&inputs.0, &inputs.1), channel)
        }
    }

    impl<F: FancyBinary + FancyBinaryConstant> CircuitInputMapper<F> for TestBinarySubtraction {
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

    impl<F: FancyBinary + FancyBinaryConstant> CircuitOutputMapper<F> for TestBinarySubtraction {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            [output.0.wires().to_vec(), vec![output.1]].concat()
        }
    }

    #[test]
    fn binary_subtraction() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        let mut rng = rand::rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = TestBinarySubtraction(nbits);

        for _ in 0..16 {
            let x = rng.random::<u128>() % q;
            let y = rng.random::<u128>() % q;
            let x_input = BinaryBundle::from((x, nbits));
            let y_input = BinaryBundle::from((y, nbits));
            let outputs = Dummy::eval(&c, (x_input, y_input)).unwrap();
            assert_eq!(Into::<u128>::into(outputs.0), x.overflowing_sub(y).0 % q);
            assert_eq!(outputs.1.val(), (y != 0 && x >= y) as u16);
        }
    }
}
