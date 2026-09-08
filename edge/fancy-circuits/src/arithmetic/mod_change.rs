use fancy_traits::{Circuit, FancyProj, HasModulus};
use swanky_channel::Channel;
use swanky_error::Result;

/// Given `(x, modulus)`, change the modulus of `x` to `modulus`.
pub struct ModChange;

impl<F: FancyProj> Circuit<F> for ModChange
where
    F::Item: HasModulus,
{
    type Input = (F::Item, u16);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, to_modulus) = inputs;

        let from_modulus = x.modulus();
        if from_modulus == to_modulus {
            return Ok(x.clone());
        }
        let tab = (0..from_modulus)
            .map(|x| x % to_modulus)
            .collect::<Vec<_>>();
        backend.proj(&x, to_modulus, Some(tab), channel)
    }
}

#[cfg(test)]
mod test {
    use crate::{arithmetic::ModChange, util::RngExt};
    use fancy_plaintext::{Dummy, DummyVal};
    use rand::{RngExt as _, rng};

    #[test]
    fn mod_change() {
        let mut rng = rng();
        for _ in 0..16 {
            let q = rng.gen_prime();
            let p = rng.gen_prime();

            let x = rng.random::<u16>() % q;
            let x_input = DummyVal::new(x, q);
            let z = Dummy::eval(&ModChange, (x_input, p)).unwrap();
            assert_eq!(z.val(), x % p);
        }
    }
}
