use crate::BinaryBundle;
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary};
use swanky_channel::Channel;
use swanky_error::Result;

/// Convert a [`BinaryBundle`] `x` into its unary vector equivalent.
///
/// # Panics
/// Panics if the length of `x` is greater than eight.
#[derive(Default)]
pub struct BinaryToUnary<'a>(PhantomData<&'a ()>);

impl<'a> BinaryToUnary<'a> {
    /// Create a new [`BinaryToUnary`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary> Circuit<F> for BinaryToUnary<'a>
where
    F::Item: 'a,
{
    type Input = &'a BinaryBundle<F::Item>;
    type Output = Vec<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let wires = inputs.wires();
        let nbits = wires.len();
        assert!(nbits <= 8, "wire bitlength is too large");

        let mut outs = Vec::with_capacity(1 << nbits);

        for ix in 0..1 << nbits {
            let mut acc = wires[0].clone();
            if (ix & 1) == 0 {
                acc = backend.negate(&acc);
            }
            for (i, w) in wires.iter().enumerate().skip(1) {
                if ((ix >> i) & 1) > 0 {
                    acc = backend.and(&acc, w, channel)?;
                } else {
                    let not_w = backend.negate(w);
                    acc = backend.and(&acc, &not_w, channel)?;
                }
            }
            outs.push(acc);
        }

        Ok(outs)
    }
}

#[cfg(test)]
mod test {
    use crate::{BinaryBundle, binary::BinaryToUnary};
    use fancy_plaintext::Dummy;
    use rand::{RngExt, rng};
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;

    #[test]
    fn binary_to_unary() {
        let mut rng = rng();
        let nbits = 8;
        let q = 1 << nbits;

        for _ in 0..16 {
            let x = rng.random::<u128>() % q;
            let x_input = BinaryBundle::from((x, nbits));
            let output = Dummy::eval(&BinaryToUnary::new(), &x_input).unwrap();
            for (i, y) in output.into_iter().enumerate() {
                if i as u128 == x {
                    assert_eq!(y.val(), F2::ONE);
                } else {
                    assert_eq!(y.val(), F2::ZERO);
                }
            }
        }
    }
}
