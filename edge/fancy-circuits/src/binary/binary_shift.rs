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
pub struct BinaryLeftShiftPad<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: Fancy, const N: usize> Circuit<F> for BinaryLeftShiftPad<'a, N>
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
pub struct BinaryLeftShift<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, const N: usize> BinaryLeftShift<'a, N> {
    /// Create a new [`BinaryLeftShift`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyConstant<F2>, const N: usize> Circuit<F> for BinaryLeftShift<'a, N>
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
        BinaryLeftShiftPad::default().execute(backend, (bundle, n, &zero), channel)
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
pub struct BinaryLeftShiftExtend<'a, const N: usize, const M: usize>(PhantomData<&'a ()>);

impl<'a, const N: usize, const M: usize> BinaryLeftShiftExtend<'a, N, M> {
    /// Create a new [`BinaryLeftShiftExtend`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyConstant<F2>, const N: usize, const M: usize> Circuit<F>
    for BinaryLeftShiftExtend<'a, N, M>
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
pub struct BinaryRightShiftPad<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, const N: usize> BinaryRightShiftPad<'a, N> {
    /// Create a new [`BinaryRightShiftPad`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyConstant<F2>, const N: usize> Circuit<F> for BinaryRightShiftPad<'a, N>
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
pub struct BinaryRightShift<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, const N: usize> BinaryRightShift<'a, N> {
    /// Create a new [`BinaryRightShift`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyConstant<F2>, const N: usize> Circuit<F> for BinaryRightShift<'a, N>
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
        BinaryRightShiftPad::new().execute(backend, (x, n, zero), channel)
    }
}

/// Arithmetic right shift.
#[derive(Default)]
pub struct BinaryArithmeticRightShift<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, const N: usize> BinaryArithmeticRightShift<'a, N> {
    /// Create a new [`BinaryArithmeticRightShift`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyConstant<F2>, const N: usize> Circuit<F> for BinaryArithmeticRightShift<'a, N>
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
        BinaryRightShiftPad::new().execute(backend, (x, n, pad.clone()), channel)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        BinaryBundle,
        binary::{
            BinaryArithmeticRightShift, BinaryLeftShift, BinaryLeftShiftExtend,
            binary_shift::BinaryRightShift,
        },
    };
    use fancy_plaintext::Dummy;
    use rand::{RngExt, rng};

    #[test]
    fn left_shift() {
        const N: usize = 64;
        let mut rng = rng();

        for _ in 0..16 {
            let x = rng.random::<u64>();
            let n = rng.random_range(..N);
            let input = BinaryBundle::from(x as u128);
            let output = Dummy::eval(&BinaryLeftShift::<N>::new(), (&input, n)).unwrap();
            assert_eq!(Into::<u128>::into(output) as u64, x.wrapping_shl(n as u32));
        }
    }

    #[test]
    fn left_shift_extend() {
        const N: usize = 64;
        const Q: u128 = 1 << N;
        let mut rng = rng();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let n = rng.random_range(..N);
            let input = BinaryBundle::from(x);
            let output =
                Dummy::eval(&BinaryLeftShiftExtend::<N, { 2 * N }>::new(), (&input, n)).unwrap();
            assert_eq!(Into::<u128>::into(output), x << n);
        }
    }

    #[test]
    fn right_shift() {
        const N: usize = 64;
        let mut rng = rng();

        for _ in 0..16 {
            let x = rng.random::<u64>();
            let n = rng.random_range(..N);
            let input = BinaryBundle::from(x as u128);
            let output = Dummy::eval(&BinaryRightShift::<N>::new(), (&input, n)).unwrap();
            assert_eq!(Into::<u128>::into(output) as u64, x >> n);
        }
    }

    #[test]
    fn arithmetic_right_shift() {
        const N: usize = 64;
        const Q: u128 = 1 << N;
        let mut rng = rng();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let n = rng.random_range(..N);
            let x_input = BinaryBundle::from(x);
            let output =
                Dummy::eval(&BinaryArithmeticRightShift::<N>::new(), (&x_input, n)).unwrap();
            assert_eq!(Into::<u128>::into(output) as i64, (x as i64) >> n);
        }
    }
}
