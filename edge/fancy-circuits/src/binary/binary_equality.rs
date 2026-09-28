use crate::{BinaryBundle, binary::AndMany};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary};
use swanky_channel::Channel;
use swanky_error::Result;

/// Binary equality.
///
/// For [`BinaryBundle`]s `x` and `y`, return `x == y`.
#[derive(Default)]
pub struct BinaryEquality<'a>(PhantomData<&'a ()>);

impl<'a> BinaryEquality<'a> {
    /// Create a new [`BinaryEquality`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary> Circuit<F> for BinaryEquality<'a>
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
        let (x, y) = inputs;
        assert_eq!(x.len(), y.len());

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
        AndMany::new().execute(backend, zs.as_slice(), channel)
    }
}

pub mod test {
    use super::*;
    use fancy_traits::CircuitInputMapper;

    /// Circuit for testing [`BinaryEquality`].
    pub struct TestBinaryEquality(pub usize);
    impl<F: FancyBinary> Circuit<F> for TestBinaryEquality {
        type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            BinaryEquality::new().execute(backend, (&inputs.0, &inputs.1), channel)
        }
    }

    impl<F: FancyBinary> CircuitInputMapper<F> for TestBinaryEquality {
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
    fn binary_equality() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        let mut rng = rand::rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = TestBinaryEquality(nbits);

        for _ in 0..16 {
            let x = rng.random::<u128>() % q;
            let y = rng.random::<u128>() % q;
            let x_input = BinaryBundle::from((x, nbits));
            let y_input = BinaryBundle::from((y, nbits));
            let output = Dummy::eval(&c, (x_input, y_input)).unwrap();
            assert_eq!(output.val() > 0, x == y);
        }

        // Test specifically for equal values
        for _ in 0..8 {
            let x = rng.random::<u128>() % q;
            let x_input = BinaryBundle::from((x, nbits));
            let output = Dummy::eval(&c, (x_input.clone(), x_input)).unwrap();
            assert_eq!(output.val(), 1);
        }
    }
}
