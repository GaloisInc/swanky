use crate::{
    CrtBundle, CrtGadgets,
    arithmetic::{
        Addition, Constant, ConstantMultiplication, Multiplication, PmrGreaterThanOrEqual,
        Subtraction,
    },
    util::product,
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyArithmetic, FancyBinary, FancyConstant, FancyProj};
use swanky_channel::Channel;
use swanky_error::Result;

/// For [`CrtBundle`]s `x` and `y`, output `x / y`.
///
/// The inputs are required to have an extra (unused) prime. That is, for
/// modulus $`Q = \prod_{i = 1,...,n} q_i`$, plaintext inputs `x` and `y` must
/// be modulo $`Q / q_n`$.
#[derive(Default)]
pub struct Division<'a>(PhantomData<&'a ()>);

impl<'a> Division<'a> {
    /// Create a new [`Division`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary + FancyArithmetic + FancyProj + CrtGadgets + FancyConstant> Circuit<F>
    for Division<'a>
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
        assert_eq!(x.moduli(), y.moduli());

        let q = x.composite_modulus();

        // Compute l based on the assumption that the last prime is unused.
        let nprimes = x.moduli().len();
        let qs_ = &x.moduli()[..nprimes - 1];
        let q_ = product(qs_);
        let l = 128 - q_.leading_zeros();

        let mut quotient = Constant::new(0, q).execute(backend, (), channel)?;
        let mut a = (*x).clone();

        let one = Constant::new(1, q).execute(backend, (), channel)?;
        for i in 0..l {
            let b = 2u128.pow(l - i - 1);
            let mut pb = q_ / b;
            if q_.is_multiple_of(b) {
                pb -= 1;
            }

            let tmp = ConstantMultiplication::new().execute(backend, (y, b), channel)?;
            let c1 = PmrGreaterThanOrEqual::new().execute(backend, (&a, &tmp), channel)?;

            let pb_crt = Constant::new(pb, q).execute(backend, (), channel)?;
            let c2 = PmrGreaterThanOrEqual::new().execute(backend, (&pb_crt, y), channel)?;

            let c = backend.and(&c1, &c2, channel)?;

            let c_ws = one
                .iter()
                .map(|w| backend.mul(w, &c, channel))
                .collect::<Result<Vec<_>>>()?;
            let c_crt = CrtBundle::new(c_ws);

            let b_if = ConstantMultiplication::new().execute(backend, (&c_crt, b), channel)?;
            quotient = Addition::new().execute(backend, (&quotient, &b_if), channel)?;

            let tmp_if = Multiplication::new().execute(backend, (&c_crt, &tmp), channel)?;
            a = Subtraction::new().execute(backend, (&a, &tmp_if), channel)?;
        }

        Ok(quotient)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        CrtBundle,
        arithmetic::Division,
        util::{RngExt, product},
    };
    use fancy_plaintext::Dummy;
    use rand::{RngExt as _, rng};

    #[test]
    fn division() {
        let mut rng = rng();

        for _ in 0..2 {
            let qs = rng.gen_usable_factors();
            let q = product(&qs);
            let q_ = product(&qs[..qs.len() - 1]);
            let x = rng.random::<u128>() % q_;
            let y = rng.random::<u128>() % q_;
            let x_input = CrtBundle::from((x, q));
            let y_input = CrtBundle::from((y, q));
            let z = Dummy::eval(&Division::new(), (&x_input, &y_input)).unwrap();
            let output = CrtBundle::from_crt(&z, q);
            assert_eq!(output, x / y);
        }
    }
}
