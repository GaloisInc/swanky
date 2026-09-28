use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary};
use swanky_channel::Channel;
use swanky_error::Result;

/// For wire slices `x` and `y`, output `x ^ y`.
///
/// # Panics
/// This panics if `x.len() ≠ y.len()`.
#[derive(Default)]
pub struct PairwiseXor<'a>(PhantomData<&'a ()>);

impl<'a> PairwiseXor<'a> {
    /// Create a new [`PairwiseXor`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary> Circuit<F> for PairwiseXor<'a>
where
    F::Item: 'a,
{
    type Input = (&'a [F::Item], &'a [F::Item]);
    type Output = Vec<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        _: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        assert_eq!(x.len(), y.len());

        Ok(x.iter()
            .zip(y.iter())
            .map(|(x, y)| backend.xor(x, y))
            .collect())
    }
}

#[cfg(test)]
pub mod test {
    use super::PairwiseXor;

    #[test]
    fn pairwise_xor() {
        use fancy_plaintext::{Dummy, DummyVal};
        use rand::RngExt;

        let mut rng = rand::rng();
        for _ in 0..100 {
            let n = 1 + rng.random_range(..200usize);
            let x = (0..n)
                .map(|_| DummyVal::rand_bool(&mut rng))
                .collect::<Vec<_>>();
            let y = (0..n)
                .map(|_| DummyVal::rand_bool(&mut rng))
                .collect::<Vec<_>>();
            let expected = x
                .iter()
                .zip(y.iter())
                .map(|(x, y)| DummyVal::new(x.val() ^ y.val(), 2))
                .collect::<Vec<_>>();
            let output = Dummy::eval(&PairwiseXor::new(), (&x, &y)).unwrap();
            assert_eq!(output, expected);
        }
    }
}
