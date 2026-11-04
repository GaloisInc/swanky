use crate::{
    BinaryBundle,
    binary::{BinaryAdder, XorMany},
};
use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary};
use swanky_channel::Channel;
use swanky_error::Result;

/// Binary addition.
///
/// For [`BinaryBundle`]s `x` and `y`, return `(x + y, c)`, where `c` is the
/// carry bit.
#[derive(Default)]
pub struct BinaryAddition<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary, const N: usize> Circuit<F> for BinaryAddition<'a, N>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item, N>, &'a BinaryBundle<F::Item, N>);
    type Output = (BinaryBundle<F::Item, N>, F::Item);

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        let xwires = x.wires();
        let ywires = y.wires();
        let (mut z, mut c) =
            BinaryAdder::default().execute(backend, (&xwires[0], &ywires[0], None), channel)?;
        let mut bs = vec![z];
        for i in 1..N {
            let res = BinaryAdder::default().execute(
                backend,
                (&xwires[i], &ywires[i], Some(&c)),
                channel,
            )?;
            z = res.0;
            c = res.1;
            bs.push(z);
        }
        Ok((
            BinaryBundle::new(bs.try_into().expect("vector should be of length `N`")),
            c,
        ))
    }
}

/// Binary addition without a carry.
///
/// For [`BinaryBundle`]s `x` and `y`, return `(x + y)`.
#[derive(Default)]
pub struct BinaryAdditionNoCarry<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary, const N: usize> Circuit<F> for BinaryAdditionNoCarry<'a, N>
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
        let (x, y) = inputs;
        let xwires = x.wires();
        let ywires = y.wires();
        let (mut z, mut c) =
            BinaryAdder::default().execute(backend, (&xwires[0], &ywires[0], None), channel)?;
        let mut bs = vec![z];
        for i in 1..N - 1 {
            let res = BinaryAdder::default().execute(
                backend,
                (&xwires[i], &ywires[i], Some(&c)),
                channel,
            )?;
            z = res.0;
            c = res.1;
            bs.push(z);
        }
        // XOR instead of using `BinaryAdder`.
        let xor_inputs = [
            xwires.last().unwrap().clone(),
            ywires.last().unwrap().clone(),
            c,
        ];
        z = XorMany::default().execute(backend, &xor_inputs[..], channel)?;
        bs.push(z);
        Ok(BinaryBundle::new(
            bs.try_into().expect("vector should be of length `N`"),
        ))
    }
}

pub mod test {
    use super::*;
    use fancy_traits::{CircuitInputMapper, CircuitOutputMapper};
    #[cfg(test)]
    use swanky_field_binary::F2;

    /// Circuit for testing [`BinaryAddition`].
    pub struct TestBinaryAddition<const N: usize>;

    impl<F: FancyBinary, const N: usize> Circuit<F> for TestBinaryAddition<N> {
        type Input = (BinaryBundle<F::Item, N>, BinaryBundle<F::Item, N>);
        type Output = (BinaryBundle<F::Item, N>, F::Item);

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            BinaryAddition::default().execute(backend, (&inputs.0, &inputs.1), channel)
        }
    }

    impl<F: FancyBinary, const N: usize> CircuitInputMapper<F> for TestBinaryAddition<N> {
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

    impl<F: FancyBinary, const N: usize> CircuitOutputMapper<F> for TestBinaryAddition<N> {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            [output.0.wires().to_vec(), vec![output.1]].concat()
        }
    }

    #[test]
    fn binary_addition() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        const N: usize = 64;
        const Q: u128 = 1 << N;

        let mut rng = rand::rng();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let y = rng.random::<u128>() % Q;
            let x_input = BinaryBundle::<_, N>::from(x);
            let y_input = BinaryBundle::<_, N>::from(y);
            let outputs = Dummy::eval(&BinaryAddition::default(), (&x_input, &y_input)).unwrap();
            assert_eq!(Into::<u128>::into(outputs.0), (x + y) % Q);
            assert_eq!(outputs.1.val(), F2::from(x + y >= Q));
        }
    }

    #[test]
    fn binary_addition_no_carry() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        const N: usize = 64;
        const Q: u128 = 1 << N;

        let mut rng = rand::rng();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let y = rng.random::<u128>() % Q;
            let x_input = BinaryBundle::<_, N>::from(x);
            let y_input = BinaryBundle::<_, N>::from(y);
            let output =
                Dummy::eval(&BinaryAdditionNoCarry::default(), (&x_input, &y_input)).unwrap();
            assert_eq!(Into::<u128>::into(output), (x + y) % Q);
        }
    }
}
