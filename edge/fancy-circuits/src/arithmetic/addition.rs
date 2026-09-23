use crate::CrtBundle;
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyArithmetic};
use swanky_channel::Channel;
use swanky_error::Result;

/// Given [`CrtBundle`]s `x` and `y`, output `x + y`.
#[derive(Default)]
pub struct Addition<'a>(PhantomData<&'a ()>);

impl<'a> Addition<'a> {
    /// Create a new [`Addition`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyArithmetic> Circuit<F> for Addition<'a>
where
    F::Item: 'a,
{
    type Input = (&'a CrtBundle<F::Item>, &'a CrtBundle<F::Item>);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        _: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        assert_eq!(x.len(), y.len(), "`x` and `y` must be the same length");
        Ok(CrtBundle::new(
            x.wires()
                .iter()
                .zip(y.wires().iter())
                .map(|(x, y)| backend.add(x, y))
                .collect(),
        ))
    }
}

/// Given inputs `x`, output `sum(x)`.
#[derive(Default)]
pub struct AddMany<'a>(PhantomData<&'a ()>);

impl<'a> AddMany<'a> {
    /// Create a new [`AddMany`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyArithmetic> Circuit<F> for AddMany<'a>
where
    F::Item: 'a,
{
    type Input = &'a [F::Item];
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        _: &mut Channel,
    ) -> Result<Self::Output> {
        assert!(inputs.len() >= 2, "`args.len()` must be two or more");
        let mut z = inputs[0].clone();
        for x in inputs.iter().skip(1) {
            z = backend.add(&z, x);
        }
        Ok(z)
    }
}

#[cfg(test)]
mod test {
    use crate::CrtBundle;
    use crate::{arithmetic::Addition, util::RngExt};
    use fancy_plaintext::Dummy;
    use rand::{RngExt as _, rng};

    #[test]
    fn addition() {
        let mut rng = rng();
        let q = rng.gen_usable_composite_modulus();

        for _ in 0..16 {
            let x = rng.random::<u128>() % q;
            let y = rng.random::<u128>() % q;
            let x_input = CrtBundle::from((x, q));
            let y_input = CrtBundle::from((y, q));
            let z = Dummy::eval(&Addition::new(), (&x_input, &y_input)).unwrap();
            let output = CrtBundle::from_crt(&z, q);
            assert_eq!(output, (x + y) % q);
        }
    }
}
