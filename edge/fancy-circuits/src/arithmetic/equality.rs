use crate::{CrtBundle, arithmetic::addition::AddMany};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyArithmetic, FancyProj, HasModulus};
use swanky_channel::Channel;
use swanky_error::Result;

/// For [`CrtBundle`]s `x` and `y`, output `x == y`.
#[derive(Default)]
pub struct Equality<'a>(PhantomData<&'a ()>);

impl<'a> Equality<'a> {
    /// Create a new [`Equality`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyArithmetic + FancyProj> Circuit<F> for Equality<'a>
where
    F::Item: HasModulus + 'a,
{
    type Input = (&'a CrtBundle<F::Item>, &'a CrtBundle<F::Item>);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        assert_eq!(x.moduli(), y.moduli());

        let wlen = x.wires().len() as u16;
        let zs = x
            .wires()
            .iter()
            .zip(y.wires().iter())
            .map(|(x, y)| {
                // compute (x-y == 0) for each residue
                let z = backend.sub(x, y);
                let mut eq_zero_tab = vec![0; x.modulus() as usize];
                eq_zero_tab[0] = 1;
                backend.proj(&z, wlen + 1, Some(eq_zero_tab), channel)
            })
            .collect::<Result<Vec<_>>>()?;
        // add up the results, and output whether they equal zero or not, mod 2
        let z = AddMany::new().execute(backend, zs.as_slice(), channel)?;
        let b = zs.len();
        let mut tab = vec![0; b + 1];
        tab[b] = 1;
        backend.proj(&z, 2, Some(tab), channel)
    }
}

#[cfg(test)]
mod test {
    use crate::{CrtBundle, arithmetic::Equality, util::RngExt};
    use fancy_plaintext::Dummy;
    use rand::{RngExt as _, rng};

    #[test]
    fn equality() {
        let mut rng = rng();
        let q = rng.gen_usable_composite_modulus();

        // Check that `x == x`.
        let x = rng.random::<u128>() % q;
        let x_input = CrtBundle::from((x, q));
        let output = Dummy::eval(&Equality::new(), (&x_input, &x_input)).unwrap();
        assert_eq!(output.val(), (x == x) as u16);

        for _ in 0..64 {
            let x = rng.random::<u128>() % q;
            let y = rng.random::<u128>() % q;
            let x_input = CrtBundle::from((x, q));
            let y_input = CrtBundle::from((y, q));
            let output = Dummy::eval(&Equality::new(), (&x_input, &y_input)).unwrap();
            assert_eq!(output.val(), (x == y) as u16);
        }
    }
}
