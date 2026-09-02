use crate::{
    BinaryBundle,
    binary::{
        BinaryAddition, BinaryAdditionNoCarry, BinaryConstant, BinaryLeftShift,
        BinaryLeftShiftExtend,
    },
    util::u128_to_bits,
};
use core::marker::PhantomData;
use fancy_traits::{
    Circuit, CircuitInputMapper, CircuitOutputMapper, FancyBinary, FancyBinaryConstant,
};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;

/// For [`BinaryBundle`] inputs `x` and `y`, output `x * y`.
#[derive(Default)]
pub struct BinaryMultiplication<'a>(PhantomData<&'a ()>);

impl<'a> BinaryMultiplication<'a> {
    /// Create a new [`BinaryMultiplication`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary + FancyBinaryConstant> Circuit<F> for BinaryMultiplication<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, &'a BinaryBundle<F::Item>);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (xs, ys) = inputs;
        assert_eq!(xs.len(), ys.len());

        let xwires = xs.wires();
        let ywires = ys.wires();

        let zero = backend.constant(F2::ZERO);

        let mut sum = xwires
            .iter()
            .map(|x| backend.and(x, &ywires[0], channel))
            .collect::<Result<_>>()
            .map(BinaryBundle::new)?;

        sum.push(zero);

        for (i, ywire) in ywires.iter().enumerate().take(xwires.len()).skip(1) {
            let mul = xwires
                .iter()
                .map(|x| backend.and(x, ywire, channel))
                .collect::<Result<_>>()
                .map(BinaryBundle::new)?;
            let shifted = BinaryLeftShiftExtend::new().execute(backend, (&mul, i), channel)?;
            let res = BinaryAddition::new().execute(backend, (&sum, &shifted), channel)?;
            sum = res.0;
            sum.push(res.1);
        }

        Ok(sum)
    }
}

/// For [`BinaryBundle`]s `x` and `y`, return the the lower-order half of `x *
/// y`.
#[derive(Default)]
pub struct BinaryMultiplicationLowerHalf<'a>(PhantomData<&'a ()>);

impl<'a> BinaryMultiplicationLowerHalf<'a> {
    /// Create a new [`BinaryMultiplicationLowerHalf`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary + FancyBinaryConstant> Circuit<F> for BinaryMultiplicationLowerHalf<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, &'a BinaryBundle<F::Item>);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (xs, ys) = inputs;
        assert_eq!(xs.len(), ys.len());

        let xwires = xs.wires();
        let ywires = ys.wires();

        let mut sum = xwires
            .iter()
            .map(|x| backend.and(x, &ywires[0], channel))
            .collect::<Result<_>>()
            .map(BinaryBundle::new)?;

        for (i, ywire) in ywires.iter().enumerate().take(xwires.len()).skip(1) {
            let mul = xwires
                .iter()
                .map(|x| backend.and(x, ywire, channel))
                .collect::<Result<_>>()
                .map(BinaryBundle::new)?;
            let shifted = BinaryLeftShift::new().execute(backend, (&mul, i), channel)?;
            sum = BinaryAdditionNoCarry::new().execute(backend, (&sum, &shifted), channel)?;
        }
        Ok(sum)
    }
}

/// For [`BinaryBundle`] `x`, constant `c`, and bitlength `n`, output `x * c`,
/// where the output is of bitlength `n`.
#[derive(Default)]
pub struct BinaryConstantMultiplication<'a>(PhantomData<&'a ()>);

impl<'a> BinaryConstantMultiplication<'a> {
    /// Create a new [`BinaryConstantMultiplication`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary + FancyBinaryConstant> Circuit<F> for BinaryConstantMultiplication<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, u128, usize);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, c, nbits) = inputs;
        let zero = BinaryConstant::new(0, nbits).execute(backend, (), channel)?;
        u128_to_bits(c, nbits)
            .into_iter()
            .enumerate()
            .filter_map(|(i, b)| if b > 0 { Some(i) } else { None })
            .try_fold(zero, |z, shift_amt| {
                let s = BinaryLeftShift::new().execute(backend, (x, shift_amt), channel)?;
                BinaryAdditionNoCarry::new().execute(backend, (&z, &s), channel)
            })
    }
}

/// Circuit for testing [`BinaryMultiplication`].
pub struct TestBinaryMultiplication<'a>(pub usize, PhantomData<&'a ()>);

impl<'a> TestBinaryMultiplication<'a> {
    /// Create a new [TestBinaryMultiplication] circuit.
    pub fn new(nbits: usize) -> Self {
        TestBinaryMultiplication(nbits, PhantomData)
    }
}

impl<'a, F: FancyBinary + FancyBinaryConstant> Circuit<F> for TestBinaryMultiplication<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, &'a BinaryBundle<F::Item>);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        BinaryMultiplication::new().execute(backend, inputs, channel)
    }
}

impl<'a, F: FancyBinary + FancyBinaryConstant> CircuitInputMapper<F>
    for TestBinaryMultiplication<'a>
where
    F::Item: 'a,
{
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), self.0 * 2);
        let (x, y) = inputs.split_at(self.0);
        let x = BinaryBundle::new(x.to_vec());
        let y = BinaryBundle::new(y.to_vec());
        // Leak memory to create static references for the test
        let x_ref: &'a BinaryBundle<F::Item> = Box::leak(Box::new(x));
        let y_ref: &'a BinaryBundle<F::Item> = Box::leak(Box::new(y));
        (x_ref, y_ref)
    }

    fn ninputs(&self) -> usize {
        self.0 * 2
    }

    fn modulus(&self, _: usize) -> u16 {
        2
    }
}

impl<'a, F: FancyBinary + FancyBinaryConstant> CircuitOutputMapper<F>
    for TestBinaryMultiplication<'a>
where
    F::Item: 'a,
{
    fn flatten(output: Self::Output) -> Vec<F::Item> {
        output.wires().to_vec()
    }
}

#[cfg(test)]
mod test {
    use crate::{
        BinaryBundle,
        binary::{
            BinaryConstantMultiplication, BinaryMultiplication, BinaryMultiplicationLowerHalf,
        },
    };
    use fancy_plaintext::Dummy;
    use rand::{RngExt, rng};

    #[test]
    fn binary_multiplication() {
        let mut rng = rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let x = rng.random::<u128>() % q;
            let y = rng.random::<u128>() % q;
            let x_input = BinaryBundle::from((x, nbits));
            let y_input = BinaryBundle::from((y, nbits));
            let output = Dummy::eval(&BinaryMultiplication::new(), (&x_input, &y_input)).unwrap();
            assert_eq!(Into::<u128>::into(output), x * y);
        }
    }

    #[test]
    fn binary_multiplication_lower_half() {
        let mut rng = rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let x = rng.random::<u128>() % q;
            let y = rng.random::<u128>() % q;
            let x_input = BinaryBundle::from((x, nbits));
            let y_input = BinaryBundle::from((y, nbits));
            let output =
                Dummy::eval(&BinaryMultiplicationLowerHalf::new(), (&x_input, &y_input)).unwrap();
            assert_eq!(Into::<u128>::into(output), (x * y) % q);
        }
    }

    #[test]
    fn binary_constant_multiplication() {
        let mut rng = rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let x = rng.random::<u128>() % q;
            let c = rng.random::<u128>() % q;
            let x_input = BinaryBundle::from((x, nbits));
            let output =
                Dummy::eval(&BinaryConstantMultiplication::new(), (&x_input, c, nbits)).unwrap();
            assert_eq!(Into::<u128>::into(output), (x * c) % q);
        }
    }
}
