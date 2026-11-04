use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary};
use swanky_channel::Channel;
use swanky_error::Result;

/// For wire slices `x` and `y`, output `x & y`.
///
/// # Panics
/// This panics if `x.len() ≠ y.len()`.
#[derive(Default)]
pub struct PairwiseAnd<'a>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary> Circuit<F> for PairwiseAnd<'a>
where
    F::Item: 'a,
{
    type Input = (&'a [F::Item], &'a [F::Item]);
    type Output = Vec<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        assert_eq!(x.len(), y.len());

        x.iter()
            .zip(y.iter())
            .map(|(x, y)| backend.and(x, y, channel))
            .collect()
    }
}

#[cfg(test)]
pub mod test {
    use super::PairwiseAnd;

    #[test]
    fn pairwise_and() {
        use fancy_plaintext::{Dummy, DummyVal};
        use rand::RngExt;

        let mut rng = rand::rng();
        let circuit = PairwiseAnd::default();

        for _ in 0..100 {
            let n = 1 + rng.random_range(..200usize);

            let x = (0..n).map(|_| DummyVal::rand(&mut rng)).collect::<Vec<_>>();
            let y = (0..n).map(|_| DummyVal::rand(&mut rng)).collect::<Vec<_>>();
            let expected = x
                .iter()
                .zip(y.iter())
                .map(|(x, y)| DummyVal::new(x.val() * y.val()))
                .collect::<Vec<_>>();
            let output = Dummy::eval(&circuit, (&x, &y)).unwrap();
            assert_eq!(output, expected);
        }
    }
}
