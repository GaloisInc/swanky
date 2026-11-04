use crate::{
    BinaryBundle,
    binary::{BinarySubtraction, Mux, OrMany},
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;

/// Binary less than.
///
/// For [`BinaryBundle`]s `x` and `y`, return `x < y`.
#[derive(Default)]
pub struct BinaryLessThan<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F> for BinaryLessThan<'a, N>
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
        let (_, lhs) = BinarySubtraction::default().execute(backend, (x, y), channel)?;

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

/// Binary signed less than.
///
/// For [`BinaryBundle`]s `x` and `y` representing signed integers in two's complement,
/// return `x < y`.
#[derive(Default)]
pub struct BinaryLessThanSigned<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F>
    for BinaryLessThanSigned<'a, N>
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
        let x_lt_y_unsigned = BinaryLessThan::default().execute(backend, (x, y), channel)?;

        // If x is negative and y is positive, then x < y.
        let x_neg_y_pos = backend.and(x_neg, &y_pos, channel)?;
        let r2 =
            Mux::default().execute(backend, (&x_neg_y_pos, &x_lt_y_unsigned, &one), channel)?;

        // If x is positive and y is negative, then !(x < y).
        let x_pos_y_neg = backend.and(&x_pos, y_neg, channel)?;
        Mux::default().execute(backend, (&x_pos_y_neg, &r2, &zero), channel)
    }
}

pub mod test {
    use super::*;
    use fancy_traits::CircuitInputMapper;

    /// Circuit for testing [`BinaryLessThan`].
    pub struct TestBinaryLessThan<const N: usize>;
    impl<F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F> for TestBinaryLessThan<N> {
        type Input = (BinaryBundle<F::Item, N>, BinaryBundle<F::Item, N>);
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            BinaryLessThan::default().execute(backend, (&inputs.0, &inputs.1), channel)
        }
    }

    impl<F: FancyBinary + FancyConstant<F2>, const N: usize> CircuitInputMapper<F>
        for TestBinaryLessThan<N>
    {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), 2 * N);
            let (x, y) = inputs.split_at(N);
            (
                BinaryBundle::new(
                    x.to_vec()
                        .try_into()
                        .expect("vector should be of length `N`"),
                ),
                BinaryBundle::new(
                    y.to_vec()
                        .try_into()
                        .expect("vector should be of length `N`"),
                ),
            )
        }

        fn ninputs(&self) -> usize {
            2 * N
        }
    }

    /// Circuit for testing [`BinaryLessThanSigned`].
    pub struct TestBinaryLessThanSigned<const N: usize>;
    impl<F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F>
        for TestBinaryLessThanSigned<N>
    {
        type Input = (BinaryBundle<F::Item, N>, BinaryBundle<F::Item, N>);
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            BinaryLessThanSigned::default().execute(backend, (&inputs.0, &inputs.1), channel)
        }
    }

    impl<F: FancyBinary + FancyConstant<F2>, const N: usize> CircuitInputMapper<F>
        for TestBinaryLessThanSigned<N>
    {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), 2 * N);
            let (x, y) = inputs.split_at(N);
            (
                BinaryBundle::new(
                    x.to_vec()
                        .try_into()
                        .expect("vector should be of length `N`"),
                ),
                BinaryBundle::new(
                    y.to_vec()
                        .try_into()
                        .expect("vector should be of length `N`"),
                ),
            )
        }

        fn ninputs(&self) -> usize {
            2 * N
        }
    }

    #[test]
    fn binary_less_than() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        const N: usize = 64;
        const Q: u128 = 1 << 64;

        let mut rng = rand::rng();
        let circuit = TestBinaryLessThan::<N>;

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let y = rng.random::<u128>() % Q;
            let x_input = BinaryBundle::from(x);
            let y_input = BinaryBundle::from(y);
            let output = Dummy::eval(&circuit, (x_input, y_input)).unwrap();
            assert_eq!(output.val(), F2::from(x < y));
        }
    }

    #[test]
    fn binary_less_than_signed() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        const N: usize = 64;
        const Q: u128 = 1 << 64;

        let mut rng = rand::rng();
        let circuit = TestBinaryLessThanSigned::<N>;

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let y = rng.random::<u128>() % Q;
            let x_input = BinaryBundle::from(x);
            let y_input = BinaryBundle::from(y);
            let output = Dummy::eval(&circuit, (x_input, y_input)).unwrap();
            assert_eq!(output.val(), F2::from((x as i64) < (y as i64)));
        }
    }
}
