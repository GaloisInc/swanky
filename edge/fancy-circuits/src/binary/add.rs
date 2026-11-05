use core::marker::PhantomData;
use fancy_traits::{Circuit, CircuitInputMapper, CircuitOutputMapper, FancyBinary};
use swanky_channel::Channel;
use swanky_error::Result;

use crate::{BinaryBundle, binary::XorMany};

/// For input bits `x` and `y` and optional carry bit `c`, return `(x + y + c,
/// c')`, where `c'` is the new carry bit.
#[derive(Default)]
pub struct AddBit<'a>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary> Circuit<F> for AddBit<'a>
where
    F::Item: 'a,
{
    type Input = (&'a F::Item, &'a F::Item, Option<&'a F::Item>);
    type Output = (F::Item, F::Item);

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y, carry_in) = inputs;
        if let Some(c) = carry_in {
            let z1 = backend.xor(x, y);
            let z2 = backend.xor(&z1, c);
            let z3 = backend.xor(x, c);
            let z4 = backend.and(&z1, &z3, channel)?;
            let carry = backend.xor(&z4, x);
            Ok((z2, carry))
        } else {
            let z = backend.xor(x, y);
            let carry = backend.and(x, y, channel)?;
            Ok((z, carry))
        }
    }
}

/// For [`BinaryBundle`]s `x` and `y`, return `(x + y, c)`, where `c` is the
/// carry bit.
#[derive(Default)]
pub struct Add<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary, const N: usize> Circuit<F> for Add<'a, N>
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
            AddBit::default().execute(backend, (&xwires[0], &ywires[0], None), channel)?;
        let mut bs = Vec::with_capacity(N);
        bs.push(z);
        for i in 1..N {
            let res =
                AddBit::default().execute(backend, (&xwires[i], &ywires[i], Some(&c)), channel)?;
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

/// Circuit for testing [`Add`].
pub struct TestAdd<const N: usize>;

impl<F: FancyBinary, const N: usize> Circuit<F> for TestAdd<N> {
    type Input = (BinaryBundle<F::Item, N>, BinaryBundle<F::Item, N>);
    type Output = (BinaryBundle<F::Item, N>, F::Item);

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        Add::default().execute(backend, (&inputs.0, &inputs.1), channel)
    }
}

impl<F: FancyBinary, const N: usize> CircuitInputMapper<F> for TestAdd<N> {
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

impl<F: FancyBinary, const N: usize> CircuitOutputMapper<F> for TestAdd<N> {
    fn flatten(output: Self::Output) -> Vec<F::Item> {
        [output.0.wires().to_vec(), vec![output.1]].concat()
    }
}

/// For [`BinaryBundle`]s `x` and `y`, return `(x + y)`.
#[derive(Default)]
pub struct AddNoCarry<'a, const N: usize>(PhantomData<&'a ()>);

impl<'a, F: FancyBinary, const N: usize> Circuit<F> for AddNoCarry<'a, N>
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
            AddBit::default().execute(backend, (&xwires[0], &ywires[0], None), channel)?;
        let mut bs = Vec::with_capacity(N);
        bs.push(z);
        for i in 1..N - 1 {
            let res =
                AddBit::default().execute(backend, (&xwires[i], &ywires[i], Some(&c)), channel)?;
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

#[cfg(test)]
mod test {
    use super::*;
    use fancy_plaintext::{Dummy, DummyVal};
    use rand::RngExt;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;

    #[test]
    fn add_bit_circuit_works() {
        let circuit = AddBit::default();
        let zero = DummyVal::new(F2::ZERO);
        let one = DummyVal::new(F2::ONE);

        let output = Dummy::eval(&circuit, (&zero, &zero, None)).unwrap();
        assert_eq!(output.0, zero);
        assert_eq!(output.1, zero);
        let output = Dummy::eval(&circuit, (&zero, &one, None)).unwrap();
        assert_eq!(output.0, one);
        assert_eq!(output.1, zero);
        let output = Dummy::eval(&circuit, (&one, &zero, None)).unwrap();
        assert_eq!(output.0, one);
        assert_eq!(output.1, zero);
        let output = Dummy::eval(&circuit, (&one, &one, None)).unwrap();
        assert_eq!(output.0, zero);
        assert_eq!(output.1, one);
    }

    #[test]
    fn add_circuit_works() {
        const N: usize = 64;
        const Q: u128 = 1 << N;

        let mut rng = rand::rng();
        let circuit = Add::default();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let y = rng.random::<u128>() % Q;
            let x_input = BinaryBundle::<_, N>::from(x);
            let y_input = BinaryBundle::<_, N>::from(y);
            let outputs = Dummy::eval(&circuit, (&x_input, &y_input)).unwrap();
            assert_eq!(Into::<u128>::into(outputs.0), (x + y) % Q);
            assert_eq!(outputs.1.val(), F2::from(x + y >= Q));
        }
    }

    #[test]
    fn binary_addition_no_carry() {
        const N: usize = 64;
        const Q: u128 = 1 << N;

        let mut rng = rand::rng();
        let circuit = AddNoCarry::default();

        for _ in 0..16 {
            let x = rng.random::<u128>() % Q;
            let y = rng.random::<u128>() % Q;
            let x_input = BinaryBundle::<_, N>::from(x);
            let y_input = BinaryBundle::<_, N>::from(y);
            let output = Dummy::eval(&circuit, (&x_input, &y_input)).unwrap();
            assert_eq!(Into::<u128>::into(output), (x + y) % Q);
        }
    }
}
