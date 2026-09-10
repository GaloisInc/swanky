use crate::{
    CrtBundle,
    arithmetic::{FractionalMixedRadix, Subtraction},
    util::get_ms,
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyArithmetic, FancyBinary, FancyProj, HasModulus};
use swanky_channel::Channel;
use swanky_error::Result;

/// For [`CrtBundle`] `x`, return 0 if `x >= 0`, 1 otherwise.
#[derive(Default)]
pub struct Sign<'a>(PhantomData<&'a ()>);

impl<'a> Sign<'a> {
    /// Create a new [`Sign`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyArithmetic + FancyProj> Circuit<F> for Sign<'a>
where
    F::Item: HasModulus + 'a,
{
    type Input = (&'a CrtBundle<F::Item>, &'a str);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, accuracy) = inputs;
        let factors_of_m = get_ms(x, accuracy);
        let res = FractionalMixedRadix::new().execute(backend, (x, &factors_of_m), channel)?;
        let p = factors_of_m.last().unwrap();
        let tt = (0..*p).map(|x| (x >= p / 2) as u16).collect::<Vec<_>>();
        backend.proj(&res, 2, Some(tt), channel)
    }
}

/// For [`CrtBundle`]s `x` and `y`, return `x < y`.
#[derive(Default)]
pub struct LessThan<'a>(PhantomData<&'a ()>);

impl<'a> LessThan<'a> {
    /// Create a new [`LessThan`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyArithmetic + FancyProj> Circuit<F> for LessThan<'a>
where
    F::Item: HasModulus + 'a,
{
    type Input = (&'a CrtBundle<F::Item>, &'a CrtBundle<F::Item>, &'a str);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y, accuracy) = inputs;
        let z = Subtraction::new().execute(backend, (x, y), channel)?;
        Sign::new().execute(backend, (&z, accuracy), channel)
    }
}

/// For [`CrtBundle`]s `x` and `y`, return `x >= y`.
#[derive(Default)]
pub struct GreaterThanOrEqual<'a>(PhantomData<&'a ()>);

impl<'a> GreaterThanOrEqual<'a> {
    /// Create a new [`GreaterThanOrEqual`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary + FancyArithmetic + FancyProj> Circuit<F> for GreaterThanOrEqual<'a>
where
    F::Item: HasModulus + 'a,
{
    type Input = (&'a CrtBundle<F::Item>, &'a CrtBundle<F::Item>, &'a str);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let z = LessThan::new().execute(backend, inputs, channel)?;
        Ok(backend.negate(&z))
    }
}

/// For a vector of [`CrtBundle`]s `xs`, return `max(xs)`.
#[derive(Default)]
pub struct Max<'a>(PhantomData<&'a ()>);

impl<'a> Max<'a> {
    /// Create a new [`Max`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary + FancyArithmetic + FancyProj> Circuit<F> for Max<'a>
where
    F::Item: HasModulus + 'a,
{
    type Input = (&'a [CrtBundle<F::Item>], &'a str);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (xs, accuracy) = inputs;
        assert!(!xs.is_empty(), "`xs` cannot be empty");

        xs.iter().skip(1).try_fold(xs[0].clone(), |x, y| {
            let pos = LessThan::new().execute(backend, (&x, y, accuracy), channel)?;
            let neg = backend.negate(&pos);
            Ok(CrtBundle::new(
                x.wires()
                    .iter()
                    .zip(y.wires().iter())
                    .map(|(x, y)| {
                        let xp = backend.mul(x, &neg, channel)?;
                        let yp = backend.mul(y, &pos, channel)?;
                        Ok(backend.add(&xp, &yp))
                    })
                    .collect::<Result<Vec<_>>>()?,
            ))
        })
    }
}

/// For [`CrtBundle`] `x`, if `x >= 0` return `1`, otherwise return `-1`, where
/// `-1` is interpreted as `Q - 1` and `Q` is the modulus of `x`.
///
/// If `output_moduli` is provided, output the result using the provided moduli.
#[derive(Default)]
pub struct Sgn<'a>(PhantomData<&'a ()>);

impl<'a> Sgn<'a> {
    /// Create a new [`Sgn`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyArithmetic + FancyProj> Circuit<F> for Sgn<'a>
where
    F::Item: HasModulus + 'a,
{
    type Input = (&'a CrtBundle<F::Item>, &'a str, Option<&'a [u16]>);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, accuracy, output_moduli) = inputs;
        let sign = Sign::new().execute(backend, (x, accuracy), channel)?;
        output_moduli
            .map(|m| m.to_vec())
            .unwrap_or_else(|| x.moduli())
            .iter()
            .map(|&p| {
                let tt = vec![1, p - 1];
                backend.proj(&sign, p, Some(tt), channel)
            })
            .collect::<Result<_>>()
            .map(CrtBundle::new)
    }
}

/// For [`CrtBundle`] `x`, output `max(0, x)`.
#[derive(Default)]
pub struct ReLU<'a>(PhantomData<&'a ()>);

impl<'a> ReLU<'a> {
    /// Create a new [`ReLU`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyArithmetic + FancyProj> Circuit<F> for ReLU<'a>
where
    F::Item: HasModulus + 'a,
{
    type Input = (&'a CrtBundle<F::Item>, &'a str, Option<&'a [u16]>);
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, accuracy, output_moduli) = inputs;
        let factors_of_m = get_ms(x, accuracy);
        let res = FractionalMixedRadix::new().execute(backend, (x, &factors_of_m), channel)?;

        // project the MSB to 0/1, whether or not it is less than p/2
        let p = *factors_of_m.last().unwrap();
        let mask_tt = (0..p).map(|x| (x < p / 2) as u16).collect::<Vec<_>>();
        let mask = backend.proj(&res, 2, Some(mask_tt), channel)?;

        // use the mask to either output x or 0
        let output_bundle = match output_moduli {
            Some(ps) => x.with_moduli(ps),
            None => (*x).clone(),
        };

        output_bundle
            .wires()
            .iter()
            .map(|x| backend.mul(x, &mask, channel))
            .collect::<Result<_>>()
            .map(CrtBundle::new)
    }
}

#[cfg(test)]
mod test {
    use crate::util::modulus_with_width;
    use crate::{
        CrtBundle,
        arithmetic::{
            ReLU, Sgn,
            comparison::{GreaterThanOrEqual, LessThan, Max, Sign},
        },
    };
    use fancy_plaintext::Dummy;
    use rand::{RngExt, rng};

    #[test]
    fn sign() {
        let mut rng = rng();
        let accuracy = "100%";
        let q = modulus_with_width(10);

        // Check that `Sign(0) == 0`.
        let x = 0;
        let x_input = CrtBundle::from((x, q));
        let output = Dummy::eval(&Sign::new(), (&x_input, accuracy)).unwrap();
        assert_eq!(output.val(), if x < q / 2 { 0 } else { 1 });

        for _ in 0..64 {
            let x = rng.random::<u128>() % q;
            let x_input = CrtBundle::from((x, q));
            let output = Dummy::eval(&Sign::new(), (&x_input, accuracy)).unwrap();
            assert_eq!(output.val(), if x < q / 2 { 0 } else { 1 });
        }
    }

    #[test]
    fn less_than() {
        let mut rng = rng();
        let accuracy = "100%";
        let q = modulus_with_width(10);

        // Check that `x < x` works.
        let x = rng.random::<u128>() % q / 2;
        let x_input = CrtBundle::from((x, q));
        let output = Dummy::eval(&LessThan::new(), (&x_input, &x_input, accuracy)).unwrap();
        assert_eq!(output.val(), (x < x) as u16);

        for _ in 0..64 {
            let x = rng.random::<u128>() % q / 2;
            let y = rng.random::<u128>() % q / 2;
            let x_input = CrtBundle::from((x, q));
            let y_input = CrtBundle::from((y, q));
            let output = Dummy::eval(&LessThan::new(), (&x_input, &y_input, accuracy)).unwrap();
            assert_eq!(output.val(), (x < y) as u16);
        }
    }

    #[test]
    fn greater_than_or_equal() {
        let mut rng = rng();
        let accuracy = "100%";
        let q = modulus_with_width(10);

        // Check that `x >= x` works.
        let x = rng.random::<u128>() % q / 2;
        let x_input = CrtBundle::from((x, q));
        let output =
            Dummy::eval(&GreaterThanOrEqual::new(), (&x_input, &x_input, accuracy)).unwrap();
        assert_eq!(output.val(), (x >= x) as u16);

        for _ in 0..64 {
            let x = rng.random::<u128>() % q / 2;
            let y = rng.random::<u128>() % q / 2;
            let x_input = CrtBundle::from((x, q));
            let y_input = CrtBundle::from((y, q));
            let output =
                Dummy::eval(&GreaterThanOrEqual::new(), (&x_input, &y_input, accuracy)).unwrap();
            assert_eq!(output.val(), (x >= y) as u16);
        }
    }

    #[test]
    fn max() {
        let mut rng = rng();
        let accuracy = "100%";
        let q = modulus_with_width(10);

        for _ in 0..16 {
            let inputs = (0..100)
                .map(|_| rng.random::<u128>() % (q / 2))
                .collect::<Vec<_>>();
            let expected = *inputs.iter().max().unwrap();

            let inputs = inputs
                .into_iter()
                .map(|x| CrtBundle::from((x, q)))
                .collect::<Vec<_>>();
            let z = Dummy::eval(&Max::new(), (&inputs[..], accuracy)).unwrap();
            let output = CrtBundle::from_crt(&z, q);
            assert_eq!(output, expected);
        }
    }

    #[test]
    fn sgn() {
        let mut rng = rng();
        let accuracy = "100%";
        let q = modulus_with_width(10);

        // Check that `Sign(0) == 1`.
        let x = 0;
        let x_input = CrtBundle::from((x, q));
        let z = Dummy::eval(&Sgn::new(), (&x_input, accuracy, None)).unwrap();
        let output = CrtBundle::from_crt(&z, q);
        assert_eq!(output, if x < q / 2 { 1 } else { q - 1 });

        for _ in 0..64 {
            let x = rng.random::<u128>() % q;
            let x_input = CrtBundle::from((x, q));
            let z = Dummy::eval(&Sgn::new(), (&x_input, accuracy, None)).unwrap();
            let output = CrtBundle::from_crt(&z, q);
            assert_eq!(output, if x < q / 2 { 1 } else { q - 1 });
        }
    }

    #[test]
    fn relu() {
        let mut rng = rng();
        let accuracy = "100%";
        let q = modulus_with_width(10);

        // Check that `Sign(0) == 1`.
        let x = 0;
        let x_input = CrtBundle::from((x, q));
        let z = Dummy::eval(&ReLU::new(), (&x_input, accuracy, None)).unwrap();
        let output = CrtBundle::from_crt(&z, q);
        assert_eq!(output, if x < q / 2 { x } else { 0 });

        for _ in 0..64 {
            let x = rng.random::<u128>() % q;
            let x_input = CrtBundle::from((x, q));
            let z = Dummy::eval(&ReLU::new(), (&x_input, accuracy, None)).unwrap();
            let output = CrtBundle::from_crt(&z, q);
            assert_eq!(output, if x < q / 2 { x } else { 0 });
        }
    }
}
