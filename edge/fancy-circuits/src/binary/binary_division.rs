use crate::{
    BinaryBundle,
    binary::{
        BinaryAddition, BinaryConstant, BinaryLeftShiftPad, BinaryMultiplex, BinaryTwosComplement,
    },
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary, FancyBinaryConstant};
use swanky_channel::Channel;
use swanky_error::Result;

/// For [`BinaryBundle`]s `x` and `y` (for `y != 0`), output `x / y`.
#[derive(Default)]
pub struct BinaryDivision<'a>(PhantomData<&'a ()>);

impl<'a> BinaryDivision<'a> {
    /// Create a new [`BinaryDivision`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary + FancyBinaryConstant> Circuit<F> for BinaryDivision<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, &'a BinaryBundle<F::Item>);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (xs, ys) = inputs;
        assert_eq!(xs.len(), ys.len());

        let ys_neg = BinaryTwosComplement::new().execute(backend, ys, channel)?;
        let mut acc = BinaryConstant::new(0, xs.len()).execute(backend, (), channel)?;
        let mut qs = BinaryBundle::new(Vec::new());
        for x in xs.wires().iter().rev() {
            acc = BinaryLeftShiftPad::new().execute(backend, (&acc, 1, x), channel)?;
            let (res, cout) =
                BinaryAddition::default().execute(backend, (&acc, &ys_neg), channel)?;
            acc = BinaryMultiplex::new().execute(backend, (cout.clone(), &acc, &res), channel)?;
            qs.push(cout);
        }
        qs.reverse(); // Switch back to little-endian
        Ok(qs)
    }
}

#[cfg(test)]
mod test {
    use crate::{BinaryBundle, binary::BinaryDivision};
    use fancy_plaintext::Dummy;
    use rand::{RngExt, rng};

    #[test]
    fn test_binary_division() {
        let mut rng = rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let x = rng.random::<u128>() % q;
            let mut y = rng.random::<u128>() % q;
            while y == 0 {
                y = rng.random::<u128>() % q;
            }
            let x_input = BinaryBundle::from((x, nbits));
            let y_input = BinaryBundle::from((y, nbits));
            let output = Dummy::eval(&BinaryDivision::new(), (&x_input, &y_input)).unwrap();
            assert_eq!(Into::<u128>::into(output), x / y);
        }
    }
}
