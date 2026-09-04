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
pub struct BinaryAddition<'a>(PhantomData<&'a ()>);

impl<'a> BinaryAddition<'a> {
    /// Create a new [`BinaryAddition`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary> Circuit<F> for BinaryAddition<'a>
where
    F::Item: 'a,
{
    type Input = (&'a BinaryBundle<F::Item>, &'a BinaryBundle<F::Item>);
    type Output = (BinaryBundle<F::Item>, F::Item);

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        assert_eq!(x.len(), y.len());
        let xwires = x.wires();
        let ywires = y.wires();
        let (mut z, mut c) =
            BinaryAdder::new().execute(backend, (&xwires[0], &ywires[0], None), channel)?;
        let mut bs = vec![z];
        for i in 1..xwires.len() {
            let res =
                BinaryAdder::new().execute(backend, (&xwires[i], &ywires[i], Some(&c)), channel)?;
            z = res.0;
            c = res.1;
            bs.push(z);
        }
        Ok((BinaryBundle::new(bs), c))
    }
}

/// Binary addition without a carry.
///
/// For [`BinaryBundle`]s `x` and `y`, return `(x + y)`.
#[derive(Default)]
pub struct BinaryAdditionNoCarry<'a>(PhantomData<&'a ()>);

impl<'a> BinaryAdditionNoCarry<'a> {
    /// Create a new [`BinaryAdditionNoCarry`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary> Circuit<F> for BinaryAdditionNoCarry<'a>
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
        let (x, y) = inputs;
        assert_eq!(x.len(), y.len());
        let xwires = x.wires();
        let ywires = y.wires();
        let (mut z, mut c) =
            BinaryAdder::new().execute(backend, (&xwires[0], &ywires[0], None), channel)?;
        let mut bs = vec![z];
        for i in 1..xwires.len() - 1 {
            let res =
                BinaryAdder::new().execute(backend, (&xwires[i], &ywires[i], Some(&c)), channel)?;
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
        z = XorMany::new().execute(backend, &xor_inputs[..], channel)?;
        bs.push(z);
        Ok(BinaryBundle::new(bs))
    }
}

pub mod test {
    use super::*;
    use fancy_traits::{CircuitInputMapper, CircuitOutputMapper};

    /// Circuit for testing [`BinaryAddition`].
    pub struct TestBinaryAddition(pub usize);

    impl<F: FancyBinary> Circuit<F> for TestBinaryAddition {
        type Input = (BinaryBundle<F::Item>, BinaryBundle<F::Item>);
        type Output = (BinaryBundle<F::Item>, F::Item);

        fn execute(
            &self,
            backend: &mut F,
            inputs: Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            BinaryAddition::new().execute(backend, (&inputs.0, &inputs.1), channel)
        }
    }

    impl<F: FancyBinary> CircuitInputMapper<F> for TestBinaryAddition {
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

    impl<F: FancyBinary> CircuitOutputMapper<F> for TestBinaryAddition {
        fn flatten(output: Self::Output) -> Vec<F::Item> {
            [output.0.wires().to_vec(), vec![output.1]].concat()
        }
    }

    #[test]
    fn binary_addition() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        let mut rng = rand::rng();
        let nbits = 64;
        let q = 1 << nbits;
        let circuit = BinaryAddition::new();

        for _ in 0..16 {
            let x = rng.random::<u128>() % q;
            let y = rng.random::<u128>() % q;
            let x_input = BinaryBundle::from((x, nbits));
            let y_input = BinaryBundle::from((y, nbits));
            let outputs = Dummy::eval(&circuit, (&x_input, &y_input)).unwrap();
            assert_eq!(Into::<u128>::into(outputs.0), (x + y) % q);
            assert_eq!(outputs.1.val(), (x + y >= q) as u16);
        }
    }

    #[test]
    fn binary_addition_no_carry() {
        use fancy_plaintext::Dummy;
        use rand::RngExt;

        let mut rng = rand::rng();
        let nbits = 64;
        let q = 1 << nbits;

        for _ in 0..16 {
            let x = rng.random::<u128>() % q;
            let y = rng.random::<u128>() % q;
            let x_input = BinaryBundle::from((x, nbits));
            let y_input = BinaryBundle::from((y, nbits));
            let output = Dummy::eval(&BinaryAdditionNoCarry::new(), (&x_input, &y_input)).unwrap();
            assert_eq!(Into::<u128>::into(output), (x + y) % q);
        }
    }
}
