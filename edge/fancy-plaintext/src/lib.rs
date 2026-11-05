//! Plaintext implementation of [`Fancy`].
#![deny(missing_docs)]

use fancy_traits::{
    BinaryBundle, BinaryEncode, Circuit, Fancy, FancyBinary, FancyConstant, FancyEncode,
    FancyOutput, u128_from_bits,
};
use rand::CryptoRng;
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field::{FiniteField, FiniteRing};
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
    /// Create a constant [`BinaryBundle`] value.
    pub fn constant<const N: usize>(value: u128) -> BinaryBundle<<Self as Fancy>::Item, N> {
        Channel::with(std::io::empty(), |channel| Dummy.bin_encode(value, channel)).unwrap()
    }

    /// Convert a [`BinaryBundle`] value into a `u128`.
    pub fn from<const N: usize>(value: BinaryBundle<DummyVal<F2>, N>) -> u128 {
        let bin = value.wires().iter().map(|w| w.val()).collect::<Vec<_>>();
        u128_from_bits(&bin)
    }

    /// Evaluate a circuit on the provided inputs in plaintext.
    pub fn eval<C: Circuit<Dummy>>(circuit: &C, inputs: C::Input) -> Result<C::Output> {
        Channel::with(std::io::empty(), |c| circuit.execute(&mut Dummy, inputs, c))
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
        DummyVal(x.val() + F2::ONE)
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
}

impl FancyOutput<F2> for Dummy {
    fn output(&mut self, x: &Self::Item, _: &mut Channel) -> Result<Option<F2>> {
        Ok(Some(x.val()))
    }
}
