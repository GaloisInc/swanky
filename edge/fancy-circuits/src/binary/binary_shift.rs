use crate::BinaryBundle;
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinaryConstant};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;

/// For a [`BinaryBundle`] `x` and an integer `n`, shift `x` left by `n`,
/// retaining the size of `x`.
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
        _: &mut Channel,
    ) -> Result<Self::Output> {
        let (bundle, n) = inputs;
        let zero = backend.constant(F2::ZERO);

        let mut wires = bundle.wires().to_vec();
        for _ in 0..n {
            wires.pop();
            wires.insert(0, zero.clone());
        }
        Ok(BinaryBundle::new(wires))
    }
}

/// For a [`BinaryBundle`] `x` and an integer `n`, shift `x` left by `n` 0s,
/// extending the [`BinaryBundle`].
///
/// That is, $`x = x_1,...,x_m`$ becomes $`x_1,...,x_m,0_1,...,0_n`$.
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

/// For a [`BinaryBundle`] `x`, integer `n`, and pad `c`, shift `x` right by
/// `n`, retaining the size of `x` and filling space on the left by `c`.
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

/// Logical right shift.
#[derive(Default)]
pub struct BinaryLogicalRightShift<'a>(PhantomData<&'a ()>);

impl<'a> BinaryLogicalRightShift<'a> {
    /// Create a new [`BinaryLogicalRightShift`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinaryConstant> Circuit<F> for BinaryLogicalRightShift<'a>
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
        BinaryRightShift::new().execute(backend, (x, n, zero), channel)
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
        BinaryRightShift::new().execute(backend, (x, n, pad.clone()), channel)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        BinaryBundle,
        binary::{
            BinaryArithmeticRightShift, BinaryLeftShift, BinaryLeftShiftExtend,
            binary_shift::BinaryLogicalRightShift,
        },
    };
    use fancy_plaintext::Dummy;
    use rand::{RngExt, rng};

    #[test]
    fn left_shift() {
        const N: usize = 64;
        let mut rng = rng();

        for _ in 0..16 {
            let shift_size = rng.random_range(..N);
            let x = rng.random::<u64>();
            let input = BinaryBundle::from((x as u128, N));
            let output =
                Dummy::eval(&BinaryLeftShift::new(), (&input, shift_size as usize)).unwrap();
            assert_eq!(
                Into::<u128>::into(output) as u64,
                x.wrapping_shl(shift_size as u32)
            );
        }
    }

    #[test]
    fn left_shift_extend() {
        let mut rng = rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let shift_size = rng.random_range(..nbits);
            let x = rng.random::<u128>() % q;
            let input = BinaryBundle::from((x, nbits));
            let output = Dummy::eval(&BinaryLeftShiftExtend::new(), (&input, shift_size)).unwrap();
            assert_eq!(Into::<u128>::into(output), x << shift_size);
        }
    }

    #[test]
    fn logical_right_shift() {
        const N: usize = 64;
        let mut rng = rng();

        for _ in 0..16 {
            let shift_size = rng.random_range(..N);
            let x = rng.random::<u64>();
            let input = BinaryBundle::from((x as u128, N));
            let output = Dummy::eval(
                &BinaryLogicalRightShift::new(),
                (&input, shift_size as usize),
            )
            .unwrap();
            assert_eq!(Into::<u128>::into(output) as u64, x >> shift_size);
        }
    }

    #[test]
    fn arithmetic_right_shift() {
        const N: usize = 64;
        const Q: u128 = 1 << N;
        let mut rng = rng();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let shift_size = rng.random_range(..N);
            let x_input = BinaryBundle::from((x, N));
            let output =
                Dummy::eval(&BinaryArithmeticRightShift::new(), (&x_input, shift_size)).unwrap();
            assert_eq!(Into::<u128>::into(output) as i64, (x as i64) >> shift_size);
        }
    }
}
