use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary};
use swanky_channel::Channel;
use swanky_error::Result;

/// Returns `true` if all inputs are `true`.
///
/// # Panics
/// Panics if no inputs are provided.
#[derive(Default)]
pub struct AndMany<'a>(PhantomData<&'a ()>);

impl<'a> AndMany<'a> {
    /// Create a new [`AndMany`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary> Circuit<F> for AndMany<'a>
where
    F::Item: 'a,
{
    type Input = &'a [F::Item];
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        assert!(!inputs.is_empty(), "`args` cannot be empty");
        inputs
            .iter()
            .skip(1)
            .try_fold(inputs[0].clone(), |acc, x| backend.and(&acc, x, channel))
    }
}

#[cfg(test)]
pub mod test {
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;

    use super::AndMany;

    #[test]
    fn and_many() {
        use fancy_plaintext::{Dummy, DummyVal};
        use rand::RngExt;

        let mut rng = rand::rng();

        for _ in 0..100 {
            let n = 2 + (rng.random_range(..200usize));
            let inputs = (0..n).map(|_| DummyVal::rand(&mut rng)).collect::<Vec<_>>();
            let expected = inputs.iter().fold(F2::ONE, |acc, &x| x.val() * acc);
            let circuit = AndMany::new();
            let output = Dummy::eval(&circuit, inputs.as_slice()).unwrap();
            assert_eq!(output.val(), expected);
        }
    }
}
