use crate::BinaryBundle;
use core::marker::PhantomData;
use fancy_traits::{Circuit, Fancy, FancyBinaryConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;

/// For [`BinaryBundle`] `x`, integer `n`, and pad `c`, compute `x << n`,
/// retaining the size of `x` and padding on the left with `c`.
#[derive(Default)]
pub struct BinaryLeftShiftPad<'a>(PhantomData<&'a ()>);

impl<'a> BinaryLeftShiftPad<'a> {
    /// Create a new [`BinaryLeftShiftPad`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: Fancy> Circuit<F> for BinaryLeftShiftPad<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, usize, &'a F::Item);
    type Output = BinaryBundle<F::Item>;

    fn execute(&self, _: &mut F, inputs: Self::Input, _: &mut Channel) -> Result<Self::Output> {
        let (bundle, n, pad) = inputs;

        let mut wires = bundle.wires().to_vec();
        for _ in 0..n {
            wires.pop();
            wires.insert(0, pad.clone());
        }
        Ok(BinaryBundle::new(wires))
    }
}

/// For [`BinaryBundle`] `x` and integer `n`, compute `x << n`, retaining the
/// size of `x`.
///
/// This is equivalent to `x.wrapping_shl(n)` in Rust.
#[derive(Default)]
pub struct BinaryLeftShift<'a>(PhantomData<&'a ()>);

impl<'a> BinaryLeftShift<'a> {
    /// Create a new [`BinaryLeftShift`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinaryConstant> Circuit<F> for BinaryLeftShift<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, usize);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (bundle, n) = inputs;
        let zero = backend.constant(F2::ZERO);
        BinaryLeftShiftPad::new().execute(backend, (bundle, n, &zero), channel)
    }
}

/// For [`BinaryBundle`] `x` and integer `n`, compute `x << n`, extending the
/// size of `x` as needed.
///
/// This is equivalent to `x << n` in Rust.
#[derive(Default)]
pub struct BinaryLeftShiftExtend<'a>(PhantomData<&'a ()>);

impl<'a> BinaryLeftShiftExtend<'a> {
    /// Create a new [`BinaryLeftShiftExtend`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinaryConstant> Circuit<F> for BinaryLeftShiftExtend<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, usize);
    type Output = BinaryBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        _: &mut Channel,
    ) -> Result<Self::Output> {
        let (bundle, n) = inputs;
        let mut wires = bundle.wires().to_vec();
        let zero = backend.constant(F2::ZERO);
        for _ in 0..n {
            wires.insert(0, zero.clone());
        }
        Ok(BinaryBundle::new(wires))
    }
}

/// For [`BinaryBundle`] `x`, integer `n`, and pad `c`, compute `x >> n`,
/// retaining the size of `x` and filling space on the left by `c`.
#[derive(Default)]
pub struct BinaryRightShiftPad<'a>(PhantomData<&'a ()>);

impl<'a> BinaryRightShiftPad<'a> {
    /// Create a new [`BinaryRightShiftPad`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinaryConstant> Circuit<F> for BinaryRightShiftPad<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, usize, F::Item);
    type Output = BinaryBundle<F::Item>;

    fn execute(&self, _: &mut F, inputs: Self::Input, _: &mut Channel) -> Result<Self::Output> {
        let (x, n, pad) = inputs;
        let mut wires: Vec<_> = Vec::with_capacity(x.wires().len());

        for i in 0..x.wires().len() {
            let src_idx = i + n;
            if src_idx >= x.wires().len() {
                wires.push(pad.clone())
            } else {
                wires.push(x.wires()[src_idx].clone())
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
pub struct BinaryRightShift<'a>(PhantomData<&'a ()>);

impl<'a> BinaryRightShift<'a> {
    /// Create a new [`BinaryRightShift`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinaryConstant> Circuit<F> for BinaryRightShift<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, usize);
    type Output = BinaryBundle<F::Item>;

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
pub struct BinaryArithmeticRightShift<'a>(PhantomData<&'a ()>);

impl<'a> BinaryArithmeticRightShift<'a> {
    /// Create a new [`BinaryArithmeticRightShift`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinaryConstant> Circuit<F> for BinaryArithmeticRightShift<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, usize);
    type Output = BinaryBundle<F::Item>;

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
            let input = BinaryBundle::from((x as u128, N));
            let output = Dummy::eval(&BinaryLeftShift::new(), (&input, n)).unwrap();
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
            let input = BinaryBundle::from((x, N));
            let output = Dummy::eval(&BinaryLeftShiftExtend::new(), (&input, n)).unwrap();
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
            let input = BinaryBundle::from((x as u128, N));
            let output = Dummy::eval(&BinaryRightShift::new(), (&input, n)).unwrap();
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
            let x_input = BinaryBundle::from((x, N));
            let output = Dummy::eval(&BinaryArithmeticRightShift::new(), (&x_input, n)).unwrap();
            assert_eq!(Into::<u128>::into(output) as i64, (x as i64) >> n);
        }
    }
}
