use crate::{BinaryBundle, util::u128_to_bits};
use fancy_traits::{Circuit, Fancy, FancyBinaryConstant};
use swanky_channel::Channel;
use swanky_error::Result;

/// Binary constant.
///
/// For `(value, nbits)`, return a [`BinaryBundle`] containing `value` in its
/// bit representation.
pub struct BinaryConstant<F: Fancy> {
    value: u128,
    nbits: usize,
    zero: Option<F::Item>,
    one: Option<F::Item>,
}

impl<F: Fancy> BinaryConstant<F> {
    /// Create a new [`BinaryConstant`] circuit for `value % 2^nbits`.
    pub fn new(value: u128, nbits: usize) -> Self {
        Self::new_with_constants(value, nbits, None, None)
    }

    /// Create a new [`BinaryConstant`] circuit for `value % 2^nbits`, using the
    /// provided zero and one constants.
    pub fn new_with_constants(
        value: u128,
        nbits: usize,
        zero: Option<F::Item>,
        one: Option<F::Item>,
    ) -> Self {
        Self {
            value,
            nbits,
            zero,
            one,
        }
    }
}

impl<F: FancyBinaryConstant> Circuit<F> for BinaryConstant<F> {
    type Input = ();
    type Output = BinaryBundle<F::Item>;

    fn execute(&self, backend: &mut F, _: Self::Input, _: &mut Channel) -> Result<Self::Output> {
        let xs = u128_to_bits(self.value, self.nbits);
        Ok(BinaryBundle::new(
            xs.into_iter()
                .map(|x| match x != 0 {
                    true => {
                        if let Some(one) = &self.one {
                            one.clone()
                        } else {
                            backend.constant(true)
                        }
                    }
                    false => {
                        if let Some(zero) = &self.zero {
                            zero.clone()
                        } else {
                            backend.constant(false)
                        }
                    }
                })
                .collect::<Vec<_>>(),
        ))
    }
}

pub mod test {
    use super::*;
    use fancy_traits::CircuitInputMapper;

    /// Circuit for testing [`BinaryConstant`].
    pub struct TestBinaryConstant(pub u128, pub usize);
    impl<F: FancyBinaryConstant> Circuit<F> for TestBinaryConstant {
        type Input = <BinaryConstant<F> as Circuit<F>>::Input;
        type Output = <BinaryConstant<F> as Circuit<F>>::Output;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut swanky_channel::Channel,
        ) -> Result<Self::Output> {
            BinaryConstant::new(self.0, self.1).execute(backend, inputs, channel)
        }
    }

    impl<F: FancyBinaryConstant> CircuitInputMapper<F> for TestBinaryConstant {
        fn map(&self, inputs: Vec<<F as Fancy>::Item>) -> Self::Input {
            assert!(inputs.is_empty());
        }

        fn ninputs(&self) -> usize {
            0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    #[test]
    fn binary_constant() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        let mut rng = rand::rng();
        for _ in 0..16 {
            let nbits = 1 + rng.random_range(..127usize);
            let value = rng.random::<u128>() % (nbits as u128);
            let c = TestBinaryConstant(value, nbits);
            let output = Dummy::eval(&c, ()).unwrap();
            assert_eq!(Into::<u128>::into(output), value);
        }
    }
}
