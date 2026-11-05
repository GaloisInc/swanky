use crate::BinaryBundle;
use core::marker::PhantomData;
use fancy_traits::{Circuit, Fancy, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;

/// For [`BinaryBundle`] `x`, integer `n`, and pad `c`, compute `x << n`,
/// retaining the size of `x` and padding on the right with `c`.
#[derive(Default)]
pub struct LeftShiftPad<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: Fancy, const N: usize> Circuit<F> for LeftShiftPad<'a, N>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item, N>, usize, &'a F::Item);
    type Output = BinaryBundle<F::Item, N>;

    fn execute(&self, _: &mut F, inputs: Self::Input, _: &mut Channel) -> Result<Self::Output> {
        let (bundle, n, pad) = inputs;

        let mut wires = bundle.wires().to_vec();
        for _ in 0..n {
            wires.pop();
            wires.insert(0, pad.clone());
        }
        Ok(BinaryBundle::new(
            wires.try_into().expect("vector should have length `N`"),
        ))
    }
}

/// For [`BinaryBundle`] `x` and integer `n`, compute `x << n`, retaining the
/// size of `x`.
///
/// This is equivalent to `x.wrapping_shl(n)` in Rust.
#[derive(Default)]
pub struct LeftShift<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyConstant<F2>, const N: usize> Circuit<F> for LeftShift<'a, N>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item, N>, usize);
    type Output = BinaryBundle<F::Item, N>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (bundle, n) = inputs;
        let zero = backend.constant(F2::ZERO);
        LeftShiftPad::default().execute(backend, (bundle, n, &zero), channel)
    }
}

/// For [`BinaryBundle`] `x` of length `N`, and shift amount `n`, compute `x << n`,
/// returning a [`BinaryBundle`] of length `M`.
///
/// This is equivalent to `x << n` in Rust.
///
/// # Panics
/// Panics if `M < N + n`.
#[derive(Default)]
pub struct LeftShiftExtend<'a, const N: usize, const M: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyConstant<F2>, const N: usize, const M: usize> Circuit<F>
    for LeftShiftExtend<'a, N, M>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item, N>, usize);
    type Output = BinaryBundle<F::Item, M>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        _: &mut Channel,
    ) -> Result<Self::Output> {
        let (bundle, n) = inputs;
        assert!(M >= N + n);
        let mut wires = bundle.wires().to_vec();
        let zero = backend.constant(F2::ZERO);
        for _ in 0..n {
            wires.insert(0, zero.clone());
        }
        for _ in 0..M - n - N {
            wires.push(zero.clone());
        }
        Ok(BinaryBundle::new(
            wires.try_into().expect("vector should be of length `M`"),
        ))
    }
}

/// For [`BinaryBundle`] `x`, integer `n`, and pad `c`, compute `x >> n`,
/// retaining the size of `x` and filling space on the left by `c`.
#[derive(Default)]
pub struct RightShiftPad<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyConstant<F2>, const N: usize> Circuit<F> for RightShiftPad<'a, N>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item, N>, usize, F::Item);
    type Output = BinaryBundle<F::Item, N>;

    fn execute(&self, _: &mut F, inputs: Self::Input, _: &mut Channel) -> Result<Self::Output> {
        let (x, n, pad) = inputs;
        let mut wires = core::array::from_fn(|_| Default::default());

        for (i, wire) in wires.iter_mut().enumerate() {
            let src_idx = i + n;
            if src_idx >= N {
                *wire = pad.clone();
            } else {
                *wire = x.wires()[src_idx].clone();
            }
        }
        Ok(BinaryBundle::new(wires))
    }
}

/// For [`BinaryBundle`] `x` and integer `n`, compute `x >> n`,
/// retaining the size of `x`.
///
/// This is equivalent to `x >> n` in Rust.
#[derive(Default)]
pub struct RightShift<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyConstant<F2>, const N: usize> Circuit<F> for RightShift<'a, N>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item, N>, usize);
    type Output = BinaryBundle<F::Item, N>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, n) = inputs;
        let zero = backend.constant(F2::ZERO);
        RightShiftPad::default().execute(backend, (x, n, zero), channel)
    }
}

/// For [`BinaryBundle`] `x` and integer `n`, compute an arithmetic right shift
/// of `x` by `n`.
///
/// This is equivalent to `(x as iN) >> n`, where `iN` is the signed
/// representation containing `N` bits.
#[derive(Default)]
pub struct ArithmeticRightShift<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyConstant<F2>, const N: usize> Circuit<F> for ArithmeticRightShift<'a, N>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item, N>, usize);
    type Output = BinaryBundle<F::Item, N>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, n) = inputs;
        let pad = x.wires().last().unwrap();
        RightShiftPad::default().execute(backend, (x, n, pad.clone()), channel)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        BinaryBundle,
        binary::{ArithmeticRightShift, LeftShift, LeftShiftExtend, shift::RightShift},
    };
    use fancy_plaintext::Dummy;
    use rand::{RngExt, rng};

    #[test]
    fn left_shift_circuit_works() {
        const N: usize = 64;

        let mut rng = rng();
        let circuit = LeftShift::<N>::default();

        for _ in 0..16 {
            let x = rng.random::<u64>();
            let n = rng.random_range(..N);
            let input = BinaryBundle::from(x as u128);
            let output = Dummy::eval(&circuit, (&input, n)).unwrap();
            assert_eq!(Into::<u128>::into(output) as u64, x.wrapping_shl(n as u32));
        }
    }

    #[test]
    fn left_shift_extend_circuit_works() {
        const N: usize = 64;
        const Q: u128 = 1 << N;

        let mut rng = rng();
        let circuit = LeftShiftExtend::<N, { 2 * N }>::default();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let n = rng.random_range(..N);
            let input = BinaryBundle::from(x);
            let output = Dummy::eval(&circuit, (&input, n)).unwrap();
            assert_eq!(Into::<u128>::into(output), x << n);
        }
    }

    #[test]
    fn right_shift_circuit_works() {
        const N: usize = 64;

        let mut rng = rng();
        let circuit = RightShift::<N>::default();

        for _ in 0..16 {
            let x = rng.random::<u64>();
            let n = rng.random_range(..N);
            let input = BinaryBundle::from(x as u128);
            let output = Dummy::eval(&circuit, (&input, n)).unwrap();
            assert_eq!(Into::<u128>::into(output) as u64, x >> n);
        }
    }

    #[test]
    fn arithmetic_right_shift_circuit_works() {
        const N: usize = 64;
        const Q: u128 = 1 << N;

        let mut rng = rng();
        let circuit = ArithmeticRightShift::<N>::default();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let n = rng.random_range(..N);
            let x_input = BinaryBundle::from(x);
            let output = Dummy::eval(&circuit, (&x_input, n)).unwrap();
            assert_eq!(Into::<u128>::into(output) as i64, (x as i64) >> n);
        }
    }
}
