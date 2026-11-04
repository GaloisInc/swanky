use crate::{BinaryBundle, binary::BinaryLessThan};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;

/// For a vector of [`BinaryBundle`]s, return the max value.
///
/// # Panics
/// This panics if the input vector is empty.
#[derive(Default)]
pub struct Max<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F> for Max<'a, N>
where
    F::Item: 'a,
{
    type Input = &'a [BinaryBundle<F::Item, N>];
    type Output = BinaryBundle<F::Item, N>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let xs = inputs;
        xs.iter().skip(1).try_fold(xs[0].clone(), |x, y| {
            // Compute `x < y`.
            let pos = BinaryLessThan::default().execute(backend, (&x, y), channel)?;
            // Compute `!(x < y)`.
            let neg = backend.negate(&pos);
            // Compute `x * (x >= y) ^ y * (x < y)`.
            let res = x
                .wires()
                .iter()
                .zip(y.wires().iter())
                .map(|(x, y)| {
                    let xp = backend.and(x, &neg, channel)?;
                    let yp = backend.and(y, &pos, channel)?;
                    Ok(backend.xor(&xp, &yp))
                })
                .collect::<Result<Vec<F::Item>>>()?;
            Ok(BinaryBundle::new(
                res.try_into().expect("vector should be of length `N`"),
            ))
        })
    }
}

#[cfg(test)]
mod test {
    use rand::RngExt;

    use super::Max;
    use crate::BinaryBundle;
    use fancy_plaintext::Dummy;

    #[test]
    fn max_circuit_works() {
        const N: usize = 64;
        const Q: u128 = 1 << N;
        let nitems = 10;

        let mut rng = rand::rng();
        let circuit = Max::default();

        for _ in 0..16 {
            let xs: Vec<u128> = (0..nitems).map(|_| rng.random::<u128>() % Q).collect();
            let max = *xs.iter().max().unwrap();
            let xs_input: Vec<BinaryBundle<_, N>> =
                xs.iter().map(|x| BinaryBundle::from(*x)).collect();
            let output = Dummy::eval(&circuit, xs_input.as_slice()).unwrap();
            assert_eq!(Into::<u128>::into(output), max);
        }
    }
}
