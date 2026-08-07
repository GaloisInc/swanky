use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary, FancyBinaryConstant};
use swanky_channel::Channel;
use swanky_error::Result;

/// For input `(b, x, y)` return `x` if `b == 0`, otherwise return `y`.
#[derive(Default)]
pub struct Mux<'a>(PhantomData<&'a ()>);

impl<'a> Mux<'a> {
    /// Create a new [`Mux`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary> Circuit<F> for Mux<'a>
where
    F::Item: 'a,
{
    type Input = (&'a F::Item, &'a F::Item, &'a F::Item);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        // The mux can be computed as `b (x ^ y) ^ x`.
        let (b, x, y) = inputs;
        let xor = backend.xor(x, y);
        let and = backend.and(b, &xor, channel)?;
        Ok(backend.xor(&and, x))
    }
}

/// For input `(b, c1, c2)`, return `c1` if `b == 0`, otherwise return `c2`.
#[derive(Default)]
pub struct MuxConstants<'a>(PhantomData<&'a ()>);

impl<'a> MuxConstants<'a> {
    /// Create a new [MuxConstants] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary + FancyBinaryConstant> Circuit<F> for MuxConstants<'a>
where
    F::Item: 'a,
{
    type Input = (&'a F::Item, bool, bool);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        _: &mut Channel,
    ) -> Result<Self::Output> {
        let (b, c1, c2) = inputs;
        Ok(match (c1, c2) {
            (false, true) => b.clone(),
            (true, false) => backend.negate(b),
            (false, false) => backend.constant(false),
            (true, true) => backend.constant(true),
        })
    }
}

#[cfg(test)]
mod test {
    use super::Mux;
    use crate::binary::mux::MuxConstants;
    use fancy_plaintext::{Dummy, DummyVal};

    #[test]
    fn mux() {
        for b in 0..=1 {
            for x in 0..=1 {
                for y in 0..=1 {
                    let b_val = DummyVal::new(b, 2);
                    let x_val = DummyVal::new(x, 2);
                    let y_val = DummyVal::new(y, 2);
                    let output = Dummy::eval(&Mux::new(), (&b_val, &x_val, &y_val)).unwrap();
                    assert_eq!(output.val(), if b == 0 { x } else { y });
                }
            }
        }
    }

    #[test]
    fn mux_constants() {
        for b in 0..=1 {
            for x in 0..=1 {
                for y in 0..=1 {
                    let b_val = DummyVal::new(b, 2);
                    let output =
                        Dummy::eval(&MuxConstants::new(), (&b_val, x != 0, y != 0)).unwrap();
                    assert_eq!(output.val(), if b == 0 { x } else { y });
                }
            }
        }
    }
}
