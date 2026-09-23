use crate::{BinaryBundle, binary::BinaryLessThan};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary, FancyBinaryConstant};
use swanky_channel::Channel;
use swanky_error::Result;

/// Binary max.
///
/// For a vector of [`BinaryBundle`]s, return the max value.
///
/// # Panics
/// This panics if the input vector is empty.
#[derive(Default)]
pub struct BinaryMax<'a>(PhantomData<&'a ()>);

impl<'a> BinaryMax<'a> {
    /// Create a new [`BinaryMax`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary + FancyBinaryConstant> Circuit<F> for BinaryMax<'a>
where
    F::Item: 'a,
{
    type Input = &'a [BinaryBundle<F::Item>];
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let xs = inputs;
        assert!(!xs.is_empty(), "`xs` cannot be empty");
        xs.iter().skip(1).try_fold(xs[0].clone(), |x, y| {
            // Compute `x < y`.
            let pos = BinaryLessThan::new().execute(backend, (&x, y), channel)?;
            // Compute `!(x < y)`.
            let neg = backend.negate(&pos);
            // Compute `x * (x >= y) ^ y * (x < y)`.
            Ok(BinaryBundle::new(
                x.wires()
                    .iter()
                    .zip(y.wires().iter())
                    .map(|(x, y)| {
                        let xp = backend.and(x, &neg, channel)?;
                        let yp = backend.and(y, &pos, channel)?;
                        Ok(backend.xor(&xp, &yp))
                    })
                    .collect::<Result<Vec<F::Item>>>()?,
            ))
        })
    }
}

#[cfg(test)]
mod test {
    use rand::RngExt;

    use super::BinaryMax;
    use crate::BinaryBundle;
    use fancy_plaintext::{Dummy, DummyVal};

    #[test]
    fn binary_max() {
        let mut rng = rand::rng();
        let nbits = 64;
        let q = 1 << nbits;
        let nitems = 10;

        for _ in 0..16 {
            let xs: Vec<u128> = (0..nitems).map(|_| rng.random::<u128>() % q).collect();
            let max = *xs.iter().max().unwrap();
            let xs_input: Vec<BinaryBundle<DummyVal>> =
                xs.iter().map(|x| BinaryBundle::from((*x, nbits))).collect();
            let output = Dummy::eval(&BinaryMax::new(), xs_input.as_slice()).unwrap();
            assert_eq!(Into::<u128>::into(output), max);
        }
    }
}
