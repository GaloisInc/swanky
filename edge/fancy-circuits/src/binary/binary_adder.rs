use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary};
use swanky_channel::Channel;
use swanky_error::Result;

/// Binary adder.
///
/// For input bits `x` and `y` and optional carry bit `c`, return `(x + y + c,
/// c')`, where `c'` is the new carry bit.
#[derive(Default)]
pub struct BinaryAdder<'a>(PhantomData<&'a ()>);

impl<'a> BinaryAdder<'a> {
    /// Create a new [`BinaryAdder`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary> Circuit<F> for BinaryAdder<'a>
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

#[cfg(test)]
pub mod test {
    use super::BinaryAdder;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;

    #[test]
    fn binary_adder() {
        use fancy_plaintext::{Dummy, DummyVal};

        let circuit = BinaryAdder::new();
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
}
