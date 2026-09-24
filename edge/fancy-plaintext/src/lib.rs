//! Plaintext implementation of [`Fancy`].
#![deny(missing_docs)]

use fancy_traits::{Circuit, Fancy, FancyBinary, FancyConstant, FancyEncode, FancyOutput};
use rand::{CryptoRng, RngExt};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result};
use swanky_field_binary::F2;

/// Plaintext implementation of [`Fancy`].
pub struct Dummy;

/// Plaintext wire value.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DummyVal {
    val: u16,
    modulus: u16,
}

impl DummyVal {
    /// Create a new [`DummyVal`].
    pub fn new(val: u16, modulus: u16) -> Self {
        Self {
            val: val % modulus,
            modulus,
        }
    }

    /// Create a new boolean [`DummyVal`].
    pub fn new_bool(val: bool) -> Self {
        Self {
            val: val as u16,
            modulus: 2,
        }
    }

    /// Extract the value.
    pub fn val(&self) -> u16 {
        self.val
    }

    /// Generate a random boolean [`DummyVal`].
    pub fn rand_bool<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        Self::rand(2, rng)
    }

    /// Generate a random [`DummyVal`].
    pub fn rand<RNG: CryptoRng>(modulus: u16, rng: &mut RNG) -> Self {
        Self::new(rng.random::<u16>(), modulus)
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
        assert_eq!(x.modulus, 2);
        assert_eq!(y.modulus, 2);

        DummyVal {
            val: (x.val + y.val) % x.modulus,
            modulus: x.modulus,
        }
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item, _: &mut Channel) -> Result<Self::Item> {
        assert_eq!(x.modulus, 2);
        assert_eq!(y.modulus, 2);

        Ok(DummyVal {
            val: x.val * y.val % x.modulus,
            modulus: x.modulus,
        })
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        assert_eq!(x.modulus, 2);

        self.xor(x, &DummyVal::new(1, 2))
    }
}

impl Fancy for Dummy {
    type Item = DummyVal;
}

impl FancyConstant<F2> for Dummy {
    fn constant(&mut self, val: F2) -> DummyVal {
        DummyVal {
            val: val.into(),
            modulus: 2,
        }
    }
}

impl FancyEncode<F2> for Dummy {
    fn encode_many(&mut self, xs: &[F2], _: &mut Channel) -> Result<Vec<DummyVal>> {
        Ok(xs.iter().map(|x| DummyVal::new((*x).into(), 2)).collect())
    }

    fn receive_many(&mut self, _: usize, _: &mut Channel) -> Result<Vec<DummyVal>> {
        // Receive is undefined for Dummy which is a single party "protocol"
        swanky_error::bail!(
            ErrorKind::UnsupportedError,
            "`receive_many` is undefined for `Dummy`"
        );
    }
}

impl FancyOutput<F2> for Dummy {
    fn output(&mut self, x: &DummyVal, _: &mut Channel) -> Result<Option<F2>> {
        Ok(Some(F2::from(x.val != 0)))
    }
}
