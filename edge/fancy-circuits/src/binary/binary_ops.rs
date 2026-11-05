use core::marker::PhantomData;
use fancy_traits::{Circuit, CircuitInputMapper, CircuitOutputMapper, FancyBinary};
use swanky_channel::Channel;
use swanky_error::Result;

/// Returns `true` if all inputs are `true`.
///
/// # Panics
/// Panics if no inputs are provided.
#[derive(Default)]
pub struct AndMany<'a>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary> Circuit<F> for AndMany<'a>
where
    F::Item: 'a,
{
    type Input = &'a [F::Item];
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        assert!(!inputs.is_empty(), "`inputs` cannot be empty");
        inputs
            .iter()
            .skip(1)
            .try_fold(inputs[0].clone(), |acc, x| backend.and(&acc, x, channel))
    }
}

/// Circuit for testing [`AndMany`].
pub struct TestAndMany(pub usize);
impl<F: FancyBinary> Circuit<F> for TestAndMany {
    type Input = Vec<F::Item>;
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        AndMany::default().execute(backend, inputs.as_slice(), channel)
    }
}
impl<F: FancyBinary> CircuitInputMapper<F> for TestAndMany {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), self.0);
        inputs
    }

    fn ninputs(&self) -> usize {
        self.0
    }
}
impl<F: FancyBinary> CircuitOutputMapper<F> for TestAndMany {
    fn flatten(output: Self::Output) -> Vec<F::Item> {
        vec![output]
    }
}

/// Returns `true` if any input is `true`.
///
/// # Panics
/// Panics if no inputs are provided.
#[derive(Default)]
pub struct OrMany<'a>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary> Circuit<F> for OrMany<'a>
where
    F::Item: 'a,
{
    type Input = &'a [F::Item];
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        assert!(!inputs.is_empty(), "`inputs` cannot be empty");
        inputs
            .iter()
            .skip(1)
            .try_fold(inputs[0].clone(), |acc, x| backend.or(&acc, x, channel))
    }
}

/// Circuit for testing [`OrMany`].
pub struct TestOrMany(pub usize);
impl<F: FancyBinary> Circuit<F> for TestOrMany {
    type Input = Vec<F::Item>;
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        OrMany::default().execute(backend, inputs.as_slice(), channel)
    }
}
impl<F: FancyBinary> CircuitInputMapper<F> for TestOrMany {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), self.0);
        inputs
    }

    fn ninputs(&self) -> usize {
        self.0
    }
}
impl<F: FancyBinary> CircuitOutputMapper<F> for TestOrMany {
    fn flatten(output: Self::Output) -> Vec<F::Item> {
        vec![output]
    }
}

/// Returns the XOR of a vector of items.
///
/// # Panics
/// Panics if no inputs are provided.
#[derive(Default)]
pub struct XorMany<'a>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary> Circuit<F> for XorMany<'a>
where
    F::Item: 'a,
{
    type Input = &'a [F::Item];
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        _: &mut Channel,
    ) -> Result<Self::Output> {
        assert!(!inputs.is_empty(), "`inputs` cannot be empty");
        Ok(inputs
            .iter()
            .skip(1)
            .fold(inputs[0].clone(), |acc, x| backend.xor(&acc, x)))
    }
}

/// Circuit for testing [`XorMany`].
pub struct TestXorMany(pub usize);
impl<F: FancyBinary> Circuit<F> for TestXorMany {
    type Input = Vec<F::Item>;
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        XorMany::default().execute(backend, inputs.as_slice(), channel)
    }
}
impl<F: FancyBinary> CircuitInputMapper<F> for TestXorMany {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), self.0);
        inputs
    }

    fn ninputs(&self) -> usize {
        self.0
    }
}
impl<F: FancyBinary> CircuitOutputMapper<F> for TestXorMany {
    fn flatten(output: Self::Output) -> Vec<F::Item> {
        vec![output]
    }
}

/// For wire slices `x` and `y`, output `x & y`.
///
/// # Panics
/// This panics if `x.len() ≠ y.len()`.
#[derive(Default)]
pub struct PairwiseAnd<'a>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary> Circuit<F> for PairwiseAnd<'a>
where
    F::Item: 'a,
{
    type Input = (&'a [F::Item], &'a [F::Item]);
    type Output = Vec<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        assert_eq!(x.len(), y.len());

        x.iter()
            .zip(y.iter())
            .map(|(x, y)| backend.and(x, y, channel))
            .collect()
    }
}

/// For wire slices `x` and `y`, output `x | y`.
///
/// # Panics
/// This panics if `x.len() ≠ y.len()`.
#[derive(Default)]
pub struct PairwiseOr<'a>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary> Circuit<F> for PairwiseOr<'a>
where
    F::Item: 'a,
{
    type Input = (&'a [F::Item], &'a [F::Item]);
    type Output = Vec<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        assert_eq!(x.len(), y.len());

        x.iter()
            .zip(y.iter())
            .map(|(x, y)| backend.or(x, y, channel))
            .collect()
    }
}

/// For wire slices `x` and `y`, output `x ^ y`.
///
/// # Panics
/// This panics if `x.len() ≠ y.len()`.
#[derive(Default)]
pub struct PairwiseXor<'a>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary> Circuit<F> for PairwiseXor<'a>
where
    F::Item: 'a,
{
    type Input = (&'a [F::Item], &'a [F::Item]);
    type Output = Vec<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        _: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        assert_eq!(x.len(), y.len());

        Ok(x.iter()
            .zip(y.iter())
            .map(|(x, y)| backend.xor(x, y))
            .collect())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use fancy_plaintext::{Dummy, DummyVal};
    use rand::RngExt;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;

    #[test]
    fn and_many_circuit_works() {
        let mut rng = rand::rng();
        let circuit = AndMany::default();

        for _ in 0..100 {
            let n = 2 + (rng.random_range(..200usize));
            let inputs = (0..n).map(|_| DummyVal::rand(&mut rng)).collect::<Vec<_>>();
            let expected = inputs.iter().fold(F2::ONE, |acc, &x| x.val() * acc);
            let output = Dummy::eval(&circuit, inputs.as_slice()).unwrap();
            assert_eq!(output.val(), expected);
        }
    }

    #[test]
    fn or_many_circuit_works() {
        let mut rng = rand::rng();
        let circuit = OrMany::default();

        for _ in 0..16 {
            let n = 2 + rng.random_range(..200usize);
            let inputs = (0..n)
                .map(|_| DummyVal::<F2>::rand(&mut rng))
                .collect::<Vec<_>>();
            let expected = inputs.iter().fold(F2::ZERO, |acc, &x| {
                F2::from(bool::from(x.val()) | bool::from(acc))
            });
            let output = Dummy::eval(&circuit, inputs.as_slice()).unwrap();
            assert_eq!(output.val(), expected);
        }
    }

    #[test]
    fn xor_many_circuit_works() {
        let mut rng = rand::rng();
        let circuit = XorMany::default();

        for _ in 0..16 {
            let n = 2 + rng.random_range(..200usize);
            let inputs = (0..n).map(|_| DummyVal::rand(&mut rng)).collect::<Vec<_>>();
            let expected = inputs.iter().fold(F2::ZERO, |acc, &x| x.val() + acc);
            let output = Dummy::eval(&circuit, inputs.as_slice()).unwrap();
            assert_eq!(output.val(), expected);
        }
    }

    #[test]
    fn pairwise_and_circuit_works() {
        let mut rng = rand::rng();
        let circuit = PairwiseAnd::default();

        for _ in 0..100 {
            let n = 1 + rng.random_range(..200usize);

            let x = (0..n).map(|_| DummyVal::rand(&mut rng)).collect::<Vec<_>>();
            let y = (0..n).map(|_| DummyVal::rand(&mut rng)).collect::<Vec<_>>();
            let expected = x
                .iter()
                .zip(y.iter())
                .map(|(x, y)| DummyVal::new(x.val() * y.val()))
                .collect::<Vec<_>>();
            let output = Dummy::eval(&circuit, (&x, &y)).unwrap();
            assert_eq!(output, expected);
        }
    }

    #[test]
    fn pairwise_or_circuit_works() {
        let mut rng = rand::rng();
        let circuit = PairwiseOr::default();
        for _ in 0..100 {
            let n = 1 + rng.random_range(..200usize);
            let x = (0..n).map(|_| DummyVal::rand(&mut rng)).collect::<Vec<_>>();
            let y = (0..n).map(|_| DummyVal::rand(&mut rng)).collect::<Vec<_>>();
            let expected = x
                .iter()
                .zip(y.iter())
                .map(|(x, y)| DummyVal::new((bool::from(x.val()) | bool::from(y.val())).into()))
                .collect::<Vec<_>>();
            let output = Dummy::eval(&circuit, (&x, &y)).unwrap();
            assert_eq!(output, expected);
        }
    }

    #[test]
    fn pairwise_xor_circuit_works() {
        let mut rng = rand::rng();
        let circuit = PairwiseXor::default();

        for _ in 0..100 {
            let n = 1 + rng.random_range(..200usize);
            let x = (0..n).map(|_| DummyVal::rand(&mut rng)).collect::<Vec<_>>();
            let y = (0..n).map(|_| DummyVal::rand(&mut rng)).collect::<Vec<_>>();
            let expected = x
                .iter()
                .zip(y.iter())
                .map(|(x, y)| DummyVal::new(x.val() + y.val()))
                .collect::<Vec<_>>();
            let output = Dummy::eval(&circuit, (&x, &y)).unwrap();
            assert_eq!(output, expected);
        }
    }
}
