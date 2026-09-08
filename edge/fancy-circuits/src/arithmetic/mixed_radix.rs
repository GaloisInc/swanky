use crate::{
    CrtBundle,
    arithmetic::{ModChange, addition::AddMany},
    util::{as_mixed_radix, inv, product},
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyArithmetic, FancyProj, HasModulus};
use swanky_channel::Channel;
use swanky_error::Result;

#[derive(Default)]
struct MixedRadixAdditionMSBOnly<'a>(PhantomData<&'a ()>);

impl<'a> MixedRadixAdditionMSBOnly<'a> {
    /// Create a new [`MixedRadixAdditionMSBOnly`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyArithmetic + FancyProj> Circuit<F> for MixedRadixAdditionMSBOnly<'a>
where
    F::Item: HasModulus + 'a,
{
    type Input = &'a [CrtBundle<F::Item>];
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let xs = inputs;
        assert!(!xs.is_empty(), "`inputs` cannot be empty");
        assert!(xs.iter().all(|x| x.moduli() == xs[0].moduli()));

        let nargs = xs.len();
        let n = xs[0].wires().len();

        let mut opt_carry = None;
        let mut max_carry = 0;

        for i in 0..n - 1 {
            // all the ith digits, in one vec
            let ds = xs.iter().map(|x| x.wires()[i].clone()).collect::<Vec<_>>();
            // compute the carry
            let q = xs[0].moduli()[i];
            // max_carry currently contains the max carry from the previous iteration
            let max_val = nargs as u16 * (q - 1) + max_carry;
            // now it is the max carry of this iteration
            max_carry = max_val / q;

            // mod change the digits to the max sum possible plus the max carry of the
            // previous iteration
            let modded_ds = ds
                .into_iter()
                .map(|d| ModChange.execute(backend, (d, max_val + 1), channel))
                .collect::<swanky_error::Result<Vec<_>>>()?;
            // add them up
            let sum = AddMany::new().execute(backend, modded_ds.as_slice(), channel)?;
            // add in the carry
            let sum_with_carry = opt_carry
                .as_ref()
                .map_or(sum.clone(), |c| backend.add(&sum, c));

            // carry now contains the carry information, we just have to project it to
            // the correct moduli for the next iteration. It will either be used to
            // compute the next carry, if i < n-2, or it will be used to compute the
            // output MSB, in which case it should be the modulus of the SB
            let next_mod = if i < n - 2 {
                nargs as u16 * (xs[0].moduli()[i + 1] - 1) + max_carry + 1
            } else {
                inputs[0].moduli()[i + 1] // we will be adding the carry to the MSB
            };

            let tt = (0..=max_val)
                .map(|i| (i / q) % next_mod)
                .collect::<Vec<_>>();
            opt_carry = Some(backend.proj(&sum_with_carry, next_mod, Some(tt), channel)?);
        }

        // compute the msb
        let ds = xs
            .iter()
            .map(|x| x.wires()[n - 1].clone())
            .collect::<Vec<_>>();
        let digit_sum = AddMany::new().execute(backend, ds.as_slice(), channel)?;
        Ok(opt_carry
            .as_ref()
            .map_or(digit_sum.clone(), |d| backend.add(&digit_sum, d)))
    }
}

/// Mixed radix addition.
#[derive(Default)]
pub struct MixedRadixAddition<'a>(PhantomData<&'a ()>);

impl<'a> MixedRadixAddition<'a> {
    /// Create a new [`MixedRadixAddition`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyArithmetic + FancyProj> Circuit<F> for MixedRadixAddition<'a>
where
    F::Item: HasModulus + 'a,
{
    type Input = &'a [CrtBundle<F::Item>];
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let xs = inputs;
        assert!(!xs.is_empty(), "`xs` cannot be empty");
        assert!(xs.iter().all(|x| x.moduli() == xs[0].moduli()));

        let nargs = xs.len();
        let n = xs[0].wires().len();

        let mut digit_carry = None;
        let mut carry_carry = None;
        let mut max_carry = 0;

        let mut res = Vec::with_capacity(n);

        for i in 0..n {
            // all the ith digits, in one vec
            let ds = xs.iter().map(|x| x.wires()[i].clone()).collect::<Vec<_>>();

            // compute the digit -- easy
            let digit_sum = AddMany::new().execute(backend, ds.as_slice(), channel)?;
            let digit = digit_carry.map_or(digit_sum.clone(), |d| backend.add(&digit_sum, &d));

            if i < n - 1 {
                // compute the carries
                let q = xs[0].wires()[i].modulus();
                // max_carry currently contains the max carry from the previous iteration
                let max_val = nargs as u16 * (q - 1) + max_carry;
                // now it is the max carry of this iteration
                max_carry = max_val / q;

                let modded_ds = ds
                    .into_iter()
                    .map(|d| ModChange.execute(backend, (d, max_val + 1), channel))
                    .collect::<Result<Vec<_>>>()?;

                let carry_sum = AddMany::new().execute(backend, modded_ds.as_slice(), channel)?;
                // add in the carry from the previous iteration
                let carry = carry_carry.map_or(carry_sum.clone(), |c| backend.add(&carry_sum, &c));

                // carry now contains the carry information, we just have to project it to
                // the correct moduli for the next iteration
                let next_mod = xs[0].wires()[i + 1].modulus();
                let tt = (0..=max_val)
                    .map(|i| (i / q) % next_mod)
                    .collect::<Vec<_>>();
                digit_carry = Some(backend.proj(&carry, next_mod, Some(tt), channel)?);

                let next_max_val = nargs as u16 * (next_mod - 1) + max_carry;

                if i < n - 2 {
                    if max_carry < next_mod {
                        carry_carry = Some(ModChange.execute(
                            backend,
                            (digit_carry.as_ref().unwrap().clone(), next_max_val + 1),
                            channel,
                        )?);
                    } else {
                        let tt = (0..=max_val).map(|i| i / q).collect::<Vec<_>>();
                        carry_carry =
                            Some(backend.proj(&carry, next_max_val + 1, Some(tt), channel)?);
                    }
                } else {
                    // next digit is MSB so we dont need carry_carry
                    carry_carry = None;
                }
            } else {
                digit_carry = None;
                carry_carry = None;
            }
            res.push(digit);
        }
        Ok(CrtBundle::new(res))
    }
}

/// For input [`CrtBundle`] `x` and vector of moduli `ms`, output the MSB of the
/// fractional part of `x / M`, where `M = product(ms)`.
#[derive(Default)]
pub struct FractionalMixedRadix<'a>(PhantomData<&'a ()>);

impl<'a> FractionalMixedRadix<'a> {
    /// Create a new [`FractionalMixedRadix`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyArithmetic + FancyProj> Circuit<F> for FractionalMixedRadix<'a>
where
    F::Item: HasModulus + 'a,
{
    type Input = (&'a CrtBundle<F::Item>, &'a [u16]);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (bun, ms) = inputs;

        let ndigits = ms.len();

        let q = product(&bun.moduli());
        let m = product(ms);

        let mut ds = Vec::new();

        for wire in bun.wires().iter() {
            let p = wire.modulus();

            let mut tabs = vec![Vec::with_capacity(p as usize); ndigits];

            for x in 0..p {
                let crt_coef = inv(((q / p as u128) % p as u128) as i128, p as i128);
                let y = (m as f64 * x as f64 * crt_coef as f64 / p as f64).round() as u128 % m;
                let digits = as_mixed_radix(y, ms);
                for i in 0..ndigits {
                    tabs[i].push(digits[i]);
                }
            }

            let new_ds = tabs
                .into_iter()
                .enumerate()
                .map(|(i, tt)| backend.proj(wire, ms[i], Some(tt), channel))
                .collect::<Result<Vec<_>>>()?;

            ds.push(CrtBundle::new(new_ds));
        }

        MixedRadixAdditionMSBOnly::new().execute(backend, ds.as_slice(), channel)
    }
}

#[cfg(test)]
mod test {
    use rand::{RngExt as _, rng};

    use crate::{
        CrtBundle,
        arithmetic::mixed_radix::{MixedRadixAddition, MixedRadixAdditionMSBOnly},
        util::{RngExt, as_mixed_radix, product},
    };
    use fancy_plaintext::Dummy;

    #[test]
    fn mixed_radix_addition_msb_only() {
        let mut rng = rng();
        let nargs = 2 + rng.random_range(..10usize);
        let moduli = (0..7).map(|_| rng.gen_modulus()).collect::<Vec<_>>();
        let q = product(&moduli);

        // Test maximum overflow.
        let inputs = (0..nargs)
            .map(|_| CrtBundle::to_mixed_radix(q - 1, &moduli))
            .collect::<Vec<_>>();
        let output = Dummy::eval(&MixedRadixAdditionMSBOnly::new(), inputs.as_slice()).unwrap();
        assert_eq!(
            output.val(),
            *as_mixed_radix((q - 1) * (nargs as u128) % q, &moduli)
                .last()
                .unwrap()
        );

        // Test random values.
        for _ in 0..4 {
            let mut expected = 0;
            let mut inputs = Vec::new();
            for _ in 0..nargs {
                let x = rng.random::<u128>() % q;
                expected = (expected + x) % q;
                inputs.push(CrtBundle::to_mixed_radix(x, &moduli));
            }
            let output = Dummy::eval(&MixedRadixAdditionMSBOnly::new(), inputs.as_slice()).unwrap();
            assert_eq!(
                output.val(),
                *as_mixed_radix(expected, &moduli).last().unwrap()
            );
        }
    }

    #[test]
    fn test_mixed_radix_addition() {
        let mut rng = rng();
        let nargs = 2 + rng.random_range(..100usize);
        let moduli = (0..7).map(|_| rng.gen_modulus()).collect::<Vec<_>>();
        let q: u128 = moduli.iter().map(|&q| q as u128).product();

        // Test maximum overflow.
        let inputs = (0..nargs)
            .map(|_| CrtBundle::to_mixed_radix(q - 1, &moduli))
            .collect::<Vec<_>>();
        let output = Dummy::eval(&MixedRadixAddition::new(), inputs.as_slice()).unwrap();
        assert_eq!(
            CrtBundle::from_mixed_radix(&output),
            (q - 1) * (nargs as u128) % q
        );

        // Test random values.
        for _ in 0..4 {
            let mut expected = 0;
            let mut inputs = Vec::new();
            for _ in 0..nargs {
                let x = rng.random::<u128>() % q;
                expected = (expected + x) % q;
                inputs.push(CrtBundle::to_mixed_radix(x, &moduli));
            }
            let output = Dummy::eval(&MixedRadixAddition::new(), inputs.as_slice()).unwrap();
            assert_eq!(CrtBundle::from_mixed_radix(&output), expected);
        }
    }
}
