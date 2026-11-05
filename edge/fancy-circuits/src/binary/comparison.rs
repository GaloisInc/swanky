use crate::binary::{MuxBit, OrMany, Sub};
use core::marker::PhantomData;
use fancy_traits::{BinaryBundle, Circuit, FancyBinary, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;

/// For [`BinaryBundle`]s `x` and `y`, return `x < y`.
#[derive(Default)]
pub struct LessThan<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F> for LessThan<'a, N>
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

        // underflow indicates y != 0 && x >= y
        // requiring special care to remove the y != 0, which is what follows.
        let (_, lhs) = Sub::default().execute(backend, (x, y), channel)?;

        // Now we build a clause equal to (y == 0 || x >= y), which we can OR with
        // lhs to remove the y==0 aspect.
        // check if y==0
        let y_contains_1 = OrMany::default().execute(backend, y.wires(), channel)?;
        let y_eq_0 = backend.negate(&y_contains_1);

        // if x != 0, then x >= y, ... assuming x is not negative
        let x_contains_1 = OrMany::default().execute(backend, x.wires(), channel)?;

        // y == 0 && x >= y
        let rhs = backend.and(&y_eq_0, &x_contains_1, channel)?;

        // (y != 0 && x >= y) || (y == 0 && x >= y)
        // => x >= y && (y != 0 || y == 0)\
        // => x >= y && 1
        // => x >= y
        let geq = backend.or(&lhs, &rhs, channel)?;
        let ngeq = backend.negate(&geq);

        let xy_neq_0 = backend.or(&y_contains_1, &x_contains_1, channel)?;
        backend.and(&xy_neq_0, &ngeq, channel)
    }
}

/// For [`BinaryBundle`]s `x` and `y` representing signed integers in two's complement,
/// return `x < y`.
#[derive(Default)]
pub struct LessThanSigned<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F> for LessThanSigned<'a, N>
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

        let zero = backend.constant(F2::ZERO);
        let one = backend.constant(F2::ONE);

        // Determine whether x and y are positive or negative.
        // In two's complement, the most significant bit indicates the sign.
        let x_neg = x.wires().last().unwrap();
        let y_neg = y.wires().last().unwrap();
        let x_pos = backend.negate(x_neg);
        let y_pos = backend.negate(y_neg);

        // Base case: if x and y have the same sign, use unsigned less than.
        let x_lt_y_unsigned = LessThan::default().execute(backend, (x, y), channel)?;

        // If x is negative and y is positive, then x < y.
        let x_neg_y_pos = backend.and(x_neg, &y_pos, channel)?;
        let r2 =
            MuxBit::default().execute(backend, (&x_neg_y_pos, &x_lt_y_unsigned, &one), channel)?;

        // If x is positive and y is negative, then !(x < y).
        let x_pos_y_neg = backend.and(&x_pos, y_neg, channel)?;
        MuxBit::default().execute(backend, (&x_pos_y_neg, &r2, &zero), channel)
    }
}

/// For [`BinaryBundle`]s `x` and `y`, return `x >= y`.
#[derive(Default)]
pub struct GreaterThanOrEqual<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F>
    for GreaterThanOrEqual<'a, N>
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
        let z = LessThan::default().execute(backend, inputs, channel)?;
        Ok(backend.negate(&z))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use fancy_plaintext::Dummy;
    use rand::RngExt;

    #[test]
    fn less_than_circuit_works() {
        const N: usize = 64;
        const Q: u128 = 1 << 64;

        let mut rng = rand::rng();
        let circuit = LessThan::<N>::default();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let y = rng.random::<u128>() % Q;
            let x_input = Dummy::constant(x);
            let y_input = Dummy::constant(y);
            let output = Dummy::eval(&circuit, (&x_input, &y_input)).unwrap();
            assert_eq!(output.val(), F2::from(x < y));
        }
    }

    #[test]
    fn less_than_signed_circuit_works() {
        const N: usize = 64;
        const Q: u128 = 1 << 64;

        let mut rng = rand::rng();
        let circuit = LessThanSigned::<N>::default();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let y = rng.random::<u128>() % Q;
            let x_input = Dummy::constant(x);
            let y_input = Dummy::constant(y);
            let output = Dummy::eval(&circuit, (&x_input, &y_input)).unwrap();
            assert_eq!(output.val(), F2::from((x as i64) < (y as i64)));
        }
    }

    #[test]
    fn greater_than_or_equal_circuit_works() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        const N: usize = 64;
        const Q: u128 = 1 << N;

        let mut rng = rand::rng();
        let circuit = GreaterThanOrEqual::<N>::default();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let y = rng.random::<u128>() % Q;
            let x_input = Dummy::constant(x);
            let y_input = Dummy::constant(y);
            let output = Dummy::eval(&circuit, (&x_input, &y_input)).unwrap();
            assert_eq!(output.val(), F2::from(x >= y));
        }
    }
}
