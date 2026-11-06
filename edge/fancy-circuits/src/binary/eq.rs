use crate::binary::AndMany;
use core::marker::PhantomData;
use fancy_traits::{BinaryBundle, Circuit, FancyBinary};
use swanky_channel::Channel;
use swanky_error::Result;

/// For [`BinaryBundle`]s `x` and `y`, return `x == y`.
#[derive(Default)]
pub struct Eq<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary, const N: usize> Circuit<F> for Eq<'a, N>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item, N>, &'a BinaryBundle<F::Item, N>);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;

        let zs = x
            .wires()
            .iter()
            .zip(y.wires().iter())
            .map(|(x, y)| {
                let xy = backend.xor(x, y);
                backend.negate(&xy)
            })
            .collect::<Vec<_>>();

        // If any negated XOR is 0, then the values are not equal
        AndMany::default().execute(backend, zs.as_slice(), channel)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;

    #[test]
    fn binary_equality() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        const N: usize = 64;
        const Q: u128 = 1 << 64;

        let mut rng = rand::rng();
        let circuit = Eq::<N>::default();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let y = rng.random::<u128>() % Q;
            let x_input = Dummy::constant(x);
            let y_input = Dummy::constant(y);
            let output = Dummy::eval(&circuit, (&x_input, &y_input)).unwrap();
            assert_eq!(output.val(), F2::from(x == y));
        }

        // Test specifically for equal values.
        for _ in 0..8 {
            let x = rng.random::<u128>() % Q;
            let x_input = Dummy::constant(x);
            let output = Dummy::eval(&circuit, (&x_input, &x_input)).unwrap();
            assert_eq!(output.val(), F2::ONE);
        }
    }
}
