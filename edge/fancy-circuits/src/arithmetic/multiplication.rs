use crate::{CrtBundle, util::crt};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyArithmetic, HasModulus};
use swanky_channel::Channel;
use swanky_error::Result;

/// Given [`CrtBundle`]s `x` and `y`, output `x * y`.
#[derive(Default)]
pub struct Multiplication<'a>(PhantomData<&'a ()>);

impl<'a> Multiplication<'a> {
    /// Create a new [`Multiplication`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyArithmetic> Circuit<F> for Multiplication<'a>
where
    F::Item: 'a,
{
    type Input = (&'a CrtBundle<F::Item>, &'a CrtBundle<F::Item>);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        assert_eq!(x.len(), y.len());
        let bundle = x
            .wires()
            .iter()
            .zip(y.wires().iter())
            .map(|(x, y)| backend.mul(x, y, channel))
            .collect::<Result<Vec<_>>>()?;
        Ok(CrtBundle::new(bundle))
    }
}

/// Given [`CrtBundle`] `x` and constant `c`, output `x * c`.
#[derive(Default)]
pub struct ConstantMultiplication<'a>(PhantomData<&'a ()>);

impl<'a> ConstantMultiplication<'a> {
    /// Create a new [`ConstantMultiplication`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyArithmetic> Circuit<F> for ConstantMultiplication<'a>
where
    F::Item: HasModulus + 'a,
{
    type Input = (&'a CrtBundle<F::Item>, u128);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        _: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, c) = inputs;
        let cs = crt(c, &x.moduli());
        Ok(CrtBundle::new(
            x.wires()
                .iter()
                .zip(cs)
                .map(|(x, c)| backend.cmul(x, c))
                .collect::<Vec<_>>(),
        ))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        CrtBundle,
        arithmetic::{ConstantMultiplication, Multiplication},
        util::RngExt,
    };
    use fancy_plaintext::Dummy;
    use rand::{RngExt as _, rng};

    #[test]
    fn multiplication() {
        let mut rng = rng();
        let q = rng.gen_usable_composite_modulus();

        for _ in 0..16 {
            let x = rng.random::<u64>() as u128 % q;
            let y = rng.random::<u64>() as u128 % q;
            let x_input = CrtBundle::from((x, q));
            let y_input = CrtBundle::from((y, q));
            let circuit = Multiplication::new();
            let z = Dummy::eval(&circuit, (&x_input, &y_input)).unwrap();
            let output = CrtBundle::from_crt(&z, q);
            assert_eq!(output, (x * y) % q);
        }
    }

    #[test]
    fn constant_multiplication() {
        let mut rng = rng();
        let q = rng.gen_usable_composite_modulus();

        for _ in 0..16 {
            let x = rng.random::<u64>() as u128 % q;
            let c = rng.random::<u64>() as u128 % q;
            let x_input = CrtBundle::from((x, q));
            let circuit = ConstantMultiplication::new();
            let z = Dummy::eval(&circuit, (&x_input, c)).unwrap();
            let output = CrtBundle::from_crt(&z, q);
            assert_eq!(output, (x * c) % q);
        }
    }
}
