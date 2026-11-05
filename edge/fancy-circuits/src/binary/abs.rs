use crate::{
    BinaryBundle,
    binary::{Mux, TwosComplement},
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;

/// For [`BinaryBundle`] `x`, output the absolute value of `x`.
///
/// This is equivalent to `if x >> (N - 1) > 0 { ((!x) + 1) & ((1 << N) - 1) }
/// else { x }`, where `N` is the length of the [`BinaryBundle`]. It is _not_
/// equivalent to either `x.abs()` or `x.unsigned_abs()` in Rust.
#[derive(Default)]
pub struct AbsoluteValue<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F> for AbsoluteValue<'a, N>
where
    F::Item: 'a,
{
    type Input = &'a BinaryBundle<F::Item, N>;
    type Output = BinaryBundle<F::Item, N>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let x = inputs;

        let sign = x.wires().last().unwrap();
        let negated = TwosComplement::default().execute(backend, x, channel)?;
        Mux::default().execute(backend, (sign.clone(), x, &negated), channel)
    }
}

#[cfg(test)]
mod test {
    use crate::{BinaryBundle, binary::AbsoluteValue};
    use fancy_plaintext::Dummy;
    use rand::{RngExt, rng};

    #[test]
    fn absolute_value_circuit_works() {
        const N: usize = 64;
        const Q: u128 = 1 << N;

        let mut rng = rng();
        let circuit = AbsoluteValue::default();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let x_input = BinaryBundle::<_, N>::from(x);
            let output = Dummy::eval(&circuit, &x_input).unwrap();
            assert_eq!(
                Into::<u128>::into(output),
                if x >> (N - 1) > 0 {
                    ((!x) + 1) & ((1 << N) - 1)
                } else {
                    x
                }
            );
        }
    }
}
