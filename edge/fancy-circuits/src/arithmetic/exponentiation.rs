use crate::CrtBundle;
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyProj, HasModulus};
use swanky_channel::Channel;
use swanky_error::Result;

/// Given a [`CrtBundle`] `x` and constant exponent `c`, output `x^c`.
///
/// This uses projection gates to compute the exponentiation for each modulus in
/// the CRT bundle.
#[derive(Default)]
pub struct ConstantExponentiation<'a>(PhantomData<&'a ()>);

impl<'a> ConstantExponentiation<'a> {
    /// Create a new [`ConstantExponentiation`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyProj> Circuit<F> for ConstantExponentiation<'a>
where
    F::Item: HasModulus + 'a,
{
    type Input = (&'a CrtBundle<F::Item>, u32);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, c) = inputs;
        x.wires()
            .iter()
            .map(|x| {
                let p = x.modulus();
                let tab = (0..p)
                    .map(|x| ((x as u64).pow(c) % p as u64) as u16)
                    .collect::<Vec<_>>();
                backend.proj(x, p, Some(tab), channel)
            })
            .collect::<Result<_>>()
            .map(CrtBundle::new)
    }
}

#[cfg(test)]
mod test {
    use crate::CrtBundle;
    use crate::{arithmetic::ConstantExponentiation, util::RngExt};
    use fancy_plaintext::Dummy;
    use rand::{RngExt as _, rng};

    #[test]
    fn constant_exponentiation() {
        let mut rng = rng();
        let q = rng.gen_usable_composite_modulus();

        for _ in 0..16 {
            let x = rng.random::<u16>() as u128 % q;
            let c = rng.random_range(2..10);
            let x_input = CrtBundle::from((x, q));
            let circuit = ConstantExponentiation::new();
            let z = Dummy::eval(&circuit, (&x_input, c)).unwrap();
            let output = CrtBundle::from_crt(&z, q);

            // Compute x^c mod q using modular arithmetic to avoid overflow
            let mut expected = 1u128;
            for _ in 0..c {
                expected = (expected * x) % q;
            }
            assert_eq!(output, expected);
        }
    }
}
