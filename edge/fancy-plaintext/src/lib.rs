//! Plaintext implementation of [`Fancy`].
#![deny(missing_docs)]

use fancy_traits::{
    Circuit, Fancy, FancyArithmetic, FancyBinary, FancyConstant, FancyBinaryConstant, FancyEncode,
    FancyOutput, FancyProj, HasModulus, is_binary,
};
use rand::{CryptoRng, Rng, RngExt};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result};

/// Plaintext implementation of [`Fancy`].
pub struct Dummy;

/// Plaintext wire value.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DummyVal {
    val: u16,
    modulus: u16,
}

impl HasModulus for DummyVal {
    fn modulus(&self) -> u16 {
        self.modulus
    }
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
    pub fn rand_bool<RNG: CryptoRng + Rng>(rng: &mut RNG) -> Self {
        Self::rand(2, rng)
    }

    /// Generate a random [`DummyVal`].
    pub fn rand<RNG: CryptoRng + Rng>(modulus: u16, rng: &mut RNG) -> Self {
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
        is_binary!(x);
        is_binary!(y);

        self.add(x, y)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item, channel: &mut Channel) -> Result<Self::Item> {
        is_binary!(x);
        is_binary!(y);

        self.mul(x, y, channel)
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        is_binary!(x);

        self.xor(x, &DummyVal::new(1, 2))
    }
}

impl FancyArithmetic for Dummy {
    fn add(&mut self, x: &DummyVal, y: &DummyVal) -> DummyVal {
        assert_eq!(x.modulus(), y.modulus());
        DummyVal {
            val: (x.val + y.val) % x.modulus,
            modulus: x.modulus,
        }
    }

    fn sub(&mut self, x: &DummyVal, y: &DummyVal) -> DummyVal {
        assert_eq!(x.modulus(), y.modulus());
        DummyVal {
            val: (x.modulus + x.val - y.val) % x.modulus,
            modulus: x.modulus,
        }
    }

    fn cmul(&mut self, x: &DummyVal, c: u16) -> DummyVal {
        DummyVal {
            val: (x.val * c) % x.modulus,
            modulus: x.modulus,
        }
    }

    fn mul(
        &mut self,
        x: &DummyVal,
        y: &DummyVal,
        _channel: &mut Channel,
    ) -> swanky_error::Result<DummyVal> {
        if x.modulus < y.modulus {
            return self.mul(y, x, _channel);
        }
        Ok(DummyVal {
            val: x.val * y.val % x.modulus,
            modulus: x.modulus,
        })
    }
}

impl FancyProj for Dummy {
    fn proj(
        &mut self,
        x: &DummyVal,
        modulus: u16,
        tt: Option<Vec<u16>>,
        _: &mut Channel,
    ) -> swanky_error::Result<DummyVal> {
        assert!(tt.is_some(), "`tt` must not be `None`");
        let tt = tt.unwrap();
        assert!(
            tt.len() >= x.modulus() as usize,
            "`tt` not large enough for `x`s modulus"
        );
        assert!(
            tt.iter().all(|&x| x < modulus),
            "`tt` value larger than `q`"
        );
        let val = tt[x.val as usize];
        Ok(DummyVal { val, modulus })
    }
}

impl Fancy for Dummy {
    type Item = DummyVal;
}

impl FancyConstant for Dummy {
    fn constant(&mut self, val: u16, modulus: u16, _: &mut Channel) -> Result<DummyVal> {
        Ok(DummyVal { val, modulus })
    }
}

impl FancyBinaryConstant for Dummy {
    fn constant(&mut self, x: bool) -> Self::Item {
        DummyVal {
            val: x as u16,
            modulus: 2,
        }
    }
}

impl FancyEncode for Dummy {
    fn encode_many(
        &mut self,
        xs: &[u16],
        moduli: &[u16],
        _: &mut Channel,
    ) -> Result<Vec<DummyVal>> {
        assert_eq!(xs.len(), moduli.len());
        Ok(xs
            .iter()
            .zip(moduli.iter())
            .map(|(x, q)| DummyVal::new(*x, *q))
            .collect())
    }

    fn receive_many(&mut self, _moduli: &[u16], _: &mut Channel) -> Result<Vec<DummyVal>> {
        // Receive is undefined for Dummy which is a single party "protocol"
        swanky_error::bail!(
            ErrorKind::UnsupportedError,
            "`receive_many` is undefined for `Dummy`"
        );
    }
}

impl FancyOutput for Dummy {
    fn output(&mut self, x: &DummyVal, _: &mut Channel) -> Result<Option<u16>> {
        Ok(Some(x.val))
    }
}
