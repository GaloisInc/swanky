use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary};
use swanky_channel::Channel;
use swanky_error::Result;

/// Returns the XOR of a vector of items.
///
/// # Panics
/// Panics if no inputs are provided.
#[derive(Default)]
pub struct XorMany<'a>(PhantomData<&'a ()>);

impl<'a> XorMany<'a> {
    /// Create a new [`XorMany`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary> Circuit<F> for XorMany<'a>
where
    F::Item: 'a,
{
    type Input = &'a [F::Item];
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        _: &mut Channel,
    ) -> Result<Self::Output> {
        assert!(!inputs.is_empty(), "`args` cannot be empty");
        Ok(inputs
            .iter()
            .skip(1)
            .fold(inputs[0].clone(), |acc, x| backend.xor(&acc, x)))
    }
}

#[cfg(test)]
pub mod test {
    use super::XorMany;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;

    #[test]
    fn xor_many() {
        use fancy_plaintext::{Dummy, DummyVal};
        use rand::RngExt;

        let mut rng = rand::rng();
        for _ in 0..16 {
            let n = 2 + rng.random_range(..200usize);
            let inputs = (0..n).map(|_| DummyVal::rand(&mut rng)).collect::<Vec<_>>();
            let expected = inputs.iter().fold(F2::ZERO, |acc, &x| x.val() + acc);
            let circuit = XorMany::new();
            let output = Dummy::eval(&circuit, inputs.as_slice()).unwrap();
            assert_eq!(output.val(), expected);
        }
    }
}
