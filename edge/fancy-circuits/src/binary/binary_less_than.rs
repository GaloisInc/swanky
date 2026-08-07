use crate::{
    BinaryBundle,
    binary::{BinarySubtraction, Mux, OrMany},
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary, FancyBinaryConstant};
use swanky_channel::Channel;
use swanky_error::Result;

/// Binary less than.
///
/// For [`BinaryBundle`]s `x` and `y`, return `x < y`.
#[derive(Default)]
pub struct BinaryLessThan<'a>(PhantomData<&'a ()>);

impl<'a> BinaryLessThan<'a> {
    /// Create a new [`BinaryLessThan`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary + FancyBinaryConstant> Circuit<F> for BinaryLessThan<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, &'a BinaryBundle<F::Item>);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        assert_eq!(inputs.0.moduli(), inputs.1.moduli());
        let (x, y) = inputs;

        // underflow indicates y != 0 && x >= y
        // requiring special care to remove the y != 0, which is what follows.
        let (_, lhs) = BinarySubtraction::new().execute(backend, (x, y), channel)?;

        // Now we build a clause equal to (y == 0 || x >= y), which we can OR with
        // lhs to remove the y==0 aspect.
        // check if y==0
        let y_contains_1 = OrMany::new().execute(backend, y.wires().as_slice(), channel)?;
        let y_eq_0 = backend.negate(&y_contains_1);

        // if x != 0, then x >= y, ... assuming x is not negative
        let x_contains_1 = OrMany::new().execute(backend, x.wires().as_slice(), channel)?;

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
pub struct BinaryLessThanSigned<'a>(PhantomData<&'a ()>);

impl<'a> BinaryLessThanSigned<'a> {
    /// Create a new [`BinaryLessThanSigned`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary + FancyBinaryConstant> Circuit<F> for BinaryLessThanSigned<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, &'a BinaryBundle<F::Item>);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        assert_eq!(inputs.0.moduli(), inputs.1.moduli());
        let (x, y) = inputs;
        let zero = backend.constant(false);
        let one = backend.constant(true);

        // Determine whether x and y are positive or negative.
        // In two's complement, the most significant bit indicates the sign.
        let x_neg = x.wires().last().unwrap();
        let y_neg = y.wires().last().unwrap();
        let x_pos = backend.negate(x_neg);
        let y_pos = backend.negate(y_neg);

        // Base case: if x and y have the same sign, use unsigned less than.
        let x_lt_y_unsigned = BinaryLessThan::new().execute(backend, (x, y), channel)?;

        // If x is negative and y is positive, then x < y.
        let x_neg_y_pos = backend.and(x_neg, &y_pos, channel)?;
        let r2 = Mux::new().execute(backend, (&x_neg_y_pos, &x_lt_y_unsigned, &one), channel)?;

        // If x is positive and y is negative, then !(x < y).
        let x_pos_y_neg = backend.and(&x_pos, y_neg, channel)?;
        Mux::new().execute(backend, (&x_pos_y_neg, &r2, &zero), channel)
    }
}

pub mod test {
    use super::*;
    use fancy_traits::CircuitInputMapper;

    /// Circuit for testing [`BinaryLessThan`].
    pub struct TestBinaryLessThan(pub usize);
    impl<F: FancyBinary + FancyBinaryConstant> Circuit<F> for TestBinaryLessThan {
        type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            BinaryLessThan::new().execute(backend, (&inputs.0, &inputs.1), channel)
        }
    }

    impl<F: FancyBinary + FancyBinaryConstant> CircuitInputMapper<F> for TestBinaryLessThan {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), self.0 * 2);
            let (x, y) = inputs.split_at(self.0);
            (BinaryBundle::new(x.to_vec()), BinaryBundle::new(y.to_vec()))
        }

        fn ninputs(&self) -> usize {
            self.0 * 2
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    /// Circuit for testing [`BinaryLessThanSigned`].
    pub struct TestBinaryLessThanSigned(pub usize);
    impl<F: FancyBinary + FancyBinaryConstant> Circuit<F> for TestBinaryLessThanSigned {
        type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            BinaryLessThanSigned::new().execute(backend, (&inputs.0, &inputs.1), channel)
        }
    }

    impl<F: FancyBinary + FancyBinaryConstant> CircuitInputMapper<F> for TestBinaryLessThanSigned {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), self.0 * 2);
            let (x, y) = inputs.split_at(self.0);
            (BinaryBundle::new(x.to_vec()), BinaryBundle::new(y.to_vec()))
        }

        fn ninputs(&self) -> usize {
            self.0 * 2
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    #[test]
    fn binary_less_than() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        let mut rng = rand::rng();
        let nbits = 64;
        let q = 1 << nbits;
        let c = TestBinaryLessThan(nbits);

        for _ in 0..16 {
            let x = rng.random::<u128>() % q;
            let y = rng.random::<u128>() % q;
            let x_input = BinaryBundle::from((x, nbits));
            let y_input = BinaryBundle::from((y, nbits));
            let output = Dummy::eval(&c, (x_input, y_input)).unwrap();
            assert_eq!(output.val() > 0, x < y);
        }
    }

    #[test]
    fn binary_less_than_signed() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        let mut rng = rand::rng();
        let nbits = 64;
        let q = 1u128 << nbits;
        let c = TestBinaryLessThanSigned(nbits);

        for _ in 0..16 {
            let x = rng.random::<u128>() % q;
            let y = rng.random::<u128>() % q;
            let x_input = BinaryBundle::from((x, nbits));
            let y_input = BinaryBundle::from((y, nbits));
            let output = Dummy::eval(&c, (x_input, y_input)).unwrap();
            assert_eq!(output.val() > 0, (x as i64) < (y as i64));
        }
    }
}
