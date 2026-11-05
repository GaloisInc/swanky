use crate::{
    BinaryBundle,
    binary::{Add, AddNoCarry, Constant, LeftShift, LeftShiftExtend},
    util::u128_to_bits,
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, CircuitInputMapper, CircuitOutputMapper, FancyBinary, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;

/// For [`BinaryBundle`] inputs `x` and `y` with length `N`, output `x * y` with
/// length `M = 2 * N`.
#[derive(Default)]
pub struct Mul<'a, const N: usize, const M: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize, const M: usize> Circuit<F>
    for Mul<'a, N, M>
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
                LeftShiftExtend::<N, M>::default().execute(backend, (&mul, i), channel)?;
            let (result, _) = Add::default().execute(backend, (&sum, &shifted), channel)?;
            sum = result;
        }

        Ok(sum)
    }
}

/// For [`BinaryBundle`]s `x` and `y` with length `N`, return `x * y % 2^N`.
#[derive(Default)]
pub struct MulLowerHalf<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize> Circuit<F> for MulLowerHalf<'a, N>
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
            let shifted = LeftShift::default().execute(backend, (&mul, i), channel)?;
            sum = AddNoCarry::default().execute(backend, (&sum, &shifted), channel)?;
        }
        Ok(sum)
    }
}

/// For [`BinaryBundle`] `x` of length `N`, and constant `c`,
/// output `x * c` with length `M = 2 * N`.
#[derive(Default)]
pub struct Mulc<'a, const N: usize, const M: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize, const M: usize> Circuit<F>
    for Mulc<'a, N, M>
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
        assert_eq!(M, 2 * N);
        let (x, c) = inputs;
        let zero = Constant::<M>::new(0).execute(backend, (), channel)?;
        u128_to_bits::<M>(c)
            .into_iter()
            .enumerate()
            .filter_map(|(i, b)| if b == F2::ONE { Some(i) } else { None })
            .try_fold(zero, |z, shift_amt| {
                let s = LeftShiftExtend::default().execute(backend, (x, shift_amt), channel)?;
                AddNoCarry::default().execute(backend, (&z, &s), channel)
            })
    }
}

/// Circuit for testing [`Mul`].
#[derive(Default)]
pub struct TestMul<'a, const N: usize, const M: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize, const M: usize> Circuit<F>
    for TestMul<'a, N, M>
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
        Mul::default().execute(backend, (&x, &y), channel)
    }
}

impl<'a, F: FancyBinary + FancyConstant<F2>, const N: usize, const M: usize> CircuitInputMapper<F>
    for TestMul<'a, N, M>
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
    for TestMul<'a, N, M>
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
        binary::{Mul, MulLowerHalf, Mulc},
    };
    use fancy_plaintext::Dummy;
    use rand::{RngExt, rng};

    const N: usize = 64;
    const Q: u128 = 1 << N;

    #[test]
    fn mul_circuit_works() {
        let mut rng = rng();
        let circuit = Mul::<N, { 2 * N }>::default();

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
    fn mul_lower_half_circuit_works() {
        let mut rng = rng();
        let circuit = MulLowerHalf::<N>::default();

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
    fn mulc_circuit_works() {
        let mut rng = rng();
        let circuit = Mulc::<N, { 2 * N }>::default();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let c = rng.random::<u128>() % Q;
            let x_input = BinaryBundle::<_, N>::from(x);
            let output = Dummy::eval(&circuit, (&x_input, c)).unwrap();
            assert_eq!(Into::<u128>::into(output), x * c);
        }
    }
}
