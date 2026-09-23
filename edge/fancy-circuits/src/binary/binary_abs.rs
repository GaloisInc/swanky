use crate::{
    BinaryBundle,
    binary::{BinaryMultiplex, BinaryTwosComplement},
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary, FancyBinaryConstant};
use swanky_channel::Channel;
use swanky_error::Result;

/// For [`BinaryBundle`] `x`, output the absolute value of `x`.
#[derive(Default)]
pub struct BinaryAbs<'a>(PhantomData<&'a ()>);

impl<'a> BinaryAbs<'a> {
    /// Create a new [`BinaryAbs`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary + FancyBinaryConstant> Circuit<F> for BinaryAbs<'a>
where
    F::Item: 'a,
{
    type Input = &'a BinaryBundle<F::Item>;
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let x = inputs;

        let sign = x.wires().last().unwrap();
        let negated = BinaryTwosComplement::new().execute(backend, x, channel)?;
        BinaryMultiplex::new().execute(backend, (sign.clone(), x, &negated), channel)
    }
}

#[cfg(test)]
mod test {
    use crate::{BinaryBundle, binary::BinaryAbs};
    use fancy_plaintext::Dummy;
    use rand::{RngExt, rng};

    #[test]
    fn binary_abs() {
        let mut rng = rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let x = rng.random::<u128>() % q;
            let x_input = BinaryBundle::from((x, nbits));
            let circuit = BinaryAbs::new();
            let output = Dummy::eval(&circuit, &x_input).unwrap();
            assert_eq!(
                Into::<u128>::into(output),
                if x >> (nbits - 1) > 0 {
                    ((!x) + 1) & ((1 << nbits) - 1)
                } else {
                    x
                }
            );
        }
    }
}
