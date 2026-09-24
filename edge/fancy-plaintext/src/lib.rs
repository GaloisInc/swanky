//! Plaintext implementation of [`Fancy`].
#![deny(missing_docs)]

use fancy_traits::{Circuit, Fancy, FancyBinary, FancyConstant, FancyEncode, FancyOutput};
use rand::CryptoRng;
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result};
use swanky_field::FiniteField;
use swanky_field_binary::F2;

/// Plaintext implementation of [`Fancy`].
pub struct Dummy;

/// Plaintext wire value.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DummyVal<FF>(FF);

impl<FF: FiniteField> DummyVal<FF> {
    /// Create a new [`DummyVal`].
    pub fn new(value: FF) -> Self {
        Self(value)
    }

    /// Extract the value.
    pub fn val(&self) -> FF {
        self.0
    }

    /// Generate a random [`DummyVal`].
    pub fn rand<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        Self::new(FF::random(rng))
    }
}

impl Dummy {
    /// Create a new [`Dummy`] instance.
    pub fn new() -> Self {
        Self
    }

    /// Evaluate a circuit on the provided inputs in plaintext.
    pub fn eval<C: Circuit<Dummy>>(circuit: &C, inputs: C::Input) -> Result<C::Output> {
        let mut dummy = Dummy::new();
        Channel::with(std::io::empty(), |c| circuit.execute(&mut dummy, inputs, c))
    }
}

impl Default for Dummy {
    fn default() -> Self {
        Self::new()
    }
}

impl FancyBinary for Dummy {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        DummyVal(x.val() + y.val())
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item, _: &mut Channel) -> Result<Self::Item> {
        Ok(DummyVal(x.val() * y.val()))
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        DummyVal(-x.val())
    }
}

impl Fancy for Dummy {
    type Item = DummyVal<F2>;
}

impl FancyConstant<F2> for Dummy {
    fn constant(&mut self, val: F2) -> Self::Item {
        DummyVal::new(val)
    }
}

impl FancyEncode<F2> for Dummy {
    fn encode_many(&mut self, xs: &[F2], _: &mut Channel) -> Result<Vec<Self::Item>> {
        Ok(xs.iter().map(|x| DummyVal::new(*x)).collect())
    }

    fn receive_many(&mut self, _: usize, _: &mut Channel) -> Result<Vec<Self::Item>> {
        // Receive is undefined for Dummy which is a single party "protocol"
        swanky_error::bail!(
            ErrorKind::UnsupportedError,
            "`receive_many` is undefined for `Dummy`"
        );
    }
}

impl FancyOutput<F2> for Dummy {
    fn output(&mut self, x: &Self::Item, _: &mut Channel) -> Result<Option<F2>> {
        Ok(Some(x.val()))
    }
}
