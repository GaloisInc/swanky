use crate::{
    BinaryBundle,
    binary::{
        BinaryAddition, BinaryAdditionNoCarry, BinaryLeftShift, BinaryLeftShiftExtend, Constant,
    },
    util::u128_to_bits,
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, CircuitInputMapper, CircuitOutputMapper, FancyBinary, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;

/// For [`BinaryBundle`] inputs `x` and `y`, output `x * y`.
#[derive(Default)]
pub struct BinaryMultiplication<'a, const N: usize, const M: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize, const M: usize> Circuit<F>
    for BinaryMultiplication<'a, N, M>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item, N>, &'a BinaryBundle<F::Item, N>);
    type Output = BinaryBundle<F::Item, M>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        assert_eq!(M, 2 * N);
        let (xs, ys) = inputs;
        let zero = backend.constant(F2::ZERO);

        let xwires = xs.wires();
        let ywires = ys.wires();

        let mut sum = xwires
            .iter()
            .map(|x| backend.and(x, &ywires[0], channel))
            .collect::<Result<Vec<_>>>()?;
        for _ in 0..N {
            sum.push(zero.clone());
        }
        let mut sum =
            BinaryBundle::new(sum.try_into().expect("vector should be of length `2 * N`"));

        for (i, ywire) in ywires.iter().enumerate().skip(1) {
            let mul = xwires
                .iter()
                .map(|x| backend.and(x, ywire, channel))
                .collect::<Result<Vec<_>>>()?;
            let mul = BinaryBundle::new(mul.try_into().expect("vector should be of length `N`"));
            let shifted =
                BinaryLeftShiftExtend::<N, M>::new().execute(backend, (&mul, i), channel)?;
            let (result, _) =
                BinaryAddition::default().execute(backend, (&sum, &shifted), channel)?;
            sum = result;
        }

        Ok(sum)
    }
}

/// For [`BinaryBundle`]s `x` and `y`, return the the lower-order half of `x *
/// y`.
#[derive(Default)]
pub struct BinaryMultiplicationLowerHalf<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F>
    for BinaryMultiplicationLowerHalf<'a, N>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item, N>, &'a BinaryBundle<F::Item, N>);
    type Output = BinaryBundle<F::Item, N>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (xs, ys) = inputs;

        let xwires = xs.wires();
        let ywires = ys.wires();

        let sum = xwires
            .iter()
            .map(|x| backend.and(x, &ywires[0], channel))
            .collect::<Result<Vec<_>>>()?;
        let mut sum = BinaryBundle::new(sum.try_into().expect("vector should be of length `N`"));

        for (i, ywire) in ywires.iter().enumerate().take(xwires.len()).skip(1) {
            let mul = xwires
                .iter()
                .map(|x| backend.and(x, ywire, channel))
                .collect::<Result<Vec<_>>>()?;
            let mul = BinaryBundle::new(mul.try_into().expect("vector should be of length `N`"));
            let shifted = BinaryLeftShift::new().execute(backend, (&mul, i), channel)?;
            sum = BinaryAdditionNoCarry::default().execute(backend, (&sum, &shifted), channel)?;
        }
        Ok(sum)
    }
}

/// For [`BinaryBundle`] `x` of length `N`, constant `c`, and bitlength `M`,
/// output `x * c`, where the output is of bitlength `M`.
#[derive(Default)]
pub struct BinaryConstantMultiplication<'a, const N: usize, const M: usize>(PhantomData<&'a ()>);

impl<'a, const N: usize, const M: usize> BinaryConstantMultiplication<'a, N, M> {
    /// Create a new [`BinaryConstantMultiplication`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize, const M: usize> Circuit<F>
    for BinaryConstantMultiplication<'a, N, M>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item, N>, u128);
    type Output = BinaryBundle<F::Item, M>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, c) = inputs;
        let zero = Constant::<M>::new(0).execute(backend, (), channel)?;
        u128_to_bits::<M>(c)
            .into_iter()
            .enumerate()
            .filter_map(|(i, b)| if b == F2::ONE { Some(i) } else { None })
            .try_fold(zero, |z, shift_amt| {
                let s = BinaryLeftShiftExtend::new().execute(backend, (x, shift_amt), channel)?;
                BinaryAdditionNoCarry::default().execute(backend, (&z, &s), channel)
            })
    }
}

/// Circuit for testing [`BinaryMultiplication`].
#[derive(Default)]
pub struct TestBinaryMultiplication<'a, const N: usize, const M: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize, const M: usize> Circuit<F>
    for TestBinaryMultiplication<'a, N, M>
where
    F::Item: 'a,
{
    type Input = (BinaryBundle<F::Item, N>, BinaryBundle<F::Item, N>);
    type Output = BinaryBundle<F::Item, M>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        BinaryMultiplication::default().execute(backend, (&x, &y), channel)
    }
}

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize, const M: usize> CircuitInputMapper<F>
    for TestBinaryMultiplication<'a, N, M>
where
    F::Item: 'a,
{
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), 2 * N);
        let (x, y) = inputs.split_at(N);
        let x = BinaryBundle::new(
            x.to_vec()
                .try_into()
                .expect("vector should be of length `N`"),
        );
        let y = BinaryBundle::new(
            y.to_vec()
                .try_into()
                .expect("vector should be of length `N`"),
        );
        (x, y)
    }

    fn ninputs(&self) -> usize {
        2 * N
    }
}

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize, const M: usize> CircuitOutputMapper<F>
    for TestBinaryMultiplication<'a, N, M>
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

    const N: usize = 64;
    const Q: u128 = 1 << N;

    #[test]
    fn binary_multiplication() {
        let mut rng = rng();
        let circuit = BinaryMultiplication::<N, { 2 * N }>::default();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let y = rng.random::<u128>() % Q;
            let x_input = BinaryBundle::from(x);
            let y_input = BinaryBundle::from(y);
            let output = Dummy::eval(&circuit, (&x_input, &y_input)).unwrap();
            assert_eq!(Into::<u128>::into(output), x * y);
        }
    }

    #[test]
    fn binary_multiplication_lower_half() {
        let mut rng = rng();
        let circuit = BinaryMultiplicationLowerHalf::<N>::default();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let y = rng.random::<u128>() % Q;
            let x_input = BinaryBundle::<_, N>::from(x);
            let y_input = BinaryBundle::<_, N>::from(y);
            let output = Dummy::eval(&circuit, (&x_input, &y_input)).unwrap();
            assert_eq!(Into::<u128>::into(output), (x * y) % Q);
        }
    }

    #[test]
    fn binary_constant_multiplication() {
        let mut rng = rng();
        let circuit = BinaryConstantMultiplication::<N, { 2 * N }>::default();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let c = rng.random::<u128>() % Q;
            let x_input = BinaryBundle::<_, N>::from(x);
            let output = Dummy::eval(&circuit, (&x_input, c)).unwrap();
            assert_eq!(Into::<u128>::into(output), x * c);
        }
    }
}
