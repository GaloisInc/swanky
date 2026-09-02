//! Module containing `CrtGadgets`, which are the CRT-based gadgets for `Fancy`.

use crate::{
    fancy::bundle::{Bundle, BundleGadgets},
    util::{self, as_mixed_radix, crt_inv_factor},
};
use fancy_plaintext::{Dummy, DummyVal};
use fancy_traits::{FancyArithmetic, FancyBinary, FancyEncode, FancyOutput, HasModulus};
use std::ops::{Deref, DerefMut};
use swanky_channel::Channel;

/// Bundle which is explicitly CRT-representation.
#[derive(Clone)]
pub struct CrtBundle<W>(Bundle<W>);

impl<W: Clone + HasModulus> CrtBundle<W> {
    /// Create a new CRT bundle from a vector of wires.
    pub fn new(ws: Vec<W>) -> CrtBundle<W> {
        CrtBundle(Bundle::new(ws))
    }

    // /// Return the moduli of all the wires in the bundle.
    pub(crate) fn moduli(&self) -> Vec<u16> {
        self.0.iter().map(HasModulus::modulus).collect()
    }

    /// Extract the underlying bundle from this CRT bundle.
    pub fn extract(self) -> Bundle<W> {
        self.0
    }

    /// Return the product of all the wires' moduli.
    pub fn composite_modulus(&self) -> u128 {
        util::product(&self.iter().map(HasModulus::modulus).collect::<Vec<_>>())
    }
}

impl From<(u128, u128)> for CrtBundle<DummyVal> {
    /// Generate a new [`CrtBundle`] for `value.0 % value.1`.
    fn from(value: (u128, u128)) -> Self {
        let mut dummy = Dummy::new();
        Channel::with(std::io::empty(), |channel| {
            dummy.crt_encode(value.0, value.1, channel)
        })
        .unwrap()
    }
}

impl CrtBundle<DummyVal> {
    /// Convert a [`Bundle`] representing a CRT value into its underlying
    /// `u128`.
    pub fn from_crt(crt: &Bundle<DummyVal>, modulus: u128) -> u128 {
        let crt = crt.wires().iter().map(|w| w.val()).collect::<Vec<_>>();
        crt_inv_factor(&crt, modulus)
    }

    /// Generate a new mixed radix form [`Bundle`] for `value` using the
    /// provided `radii`.
    pub fn to_mixed_radix(value: u128, radii: &[u16]) -> Self {
        let mixed = as_mixed_radix(value, radii);
        let mixed = mixed
            .into_iter()
            .zip(radii)
            .map(|(x, q)| DummyVal::new(x, *q))
            .collect::<Vec<_>>();
        CrtBundle::new(mixed)
    }

    /// Convert a [`Bundle`] representing mixed radix form into its underlying
    /// `u128`.
    pub fn from_mixed_radix(bundle: &Self) -> u128 {
        let mut x: u128 = 0;
        for wire in bundle.wires().iter().rev() {
            let (xp, overflow) = x.overflowing_mul(wire.modulus() as u128);
            assert!(!overflow);
            x = xp + wire.val() as u128;
        }
        x
    }
}

impl<W: Clone + HasModulus> Deref for CrtBundle<W> {
    type Target = Bundle<W>;

    fn deref(&self) -> &Bundle<W> {
        &self.0
    }
}

impl<W: Clone + HasModulus> DerefMut for CrtBundle<W> {
    fn deref_mut(&mut self) -> &mut Bundle<W> {
        &mut self.0
    }
}

impl<W: Clone + HasModulus> From<Bundle<W>> for CrtBundle<W> {
    fn from(b: Bundle<W>) -> CrtBundle<W> {
        CrtBundle(b)
    }
}

impl<F: FancyArithmetic + FancyBinary + FancyEncode + FancyOutput> CrtGadgets for F {}

/// Extension trait for `Fancy` providing advanced CRT gadgets based on bundles of wires.
pub trait CrtGadgets: BundleGadgets + FancyEncode {
    /// Encode a CRT input bundle.
    fn crt_encode(
        &mut self,
        value: u128,
        modulus: u128,
        channel: &mut Channel,
    ) -> swanky_error::Result<CrtBundle<Self::Item>> {
        let qs = util::factor(modulus);
        let xs = util::crt(value, &qs);
        self.encode_many(&xs, &qs, channel).map(CrtBundle::new)
    }

    /// Receive an CRT input bundle.
    fn crt_receive(
        &mut self,
        modulus: u128,
        channel: &mut Channel,
    ) -> swanky_error::Result<CrtBundle<Self::Item>> {
        let qs = util::factor(modulus);
        self.receive_many(&qs, channel).map(CrtBundle::new)
    }

    /// Encode many CRT input bundles.
    fn crt_encode_many(
        &mut self,
        values: &[u128],
        modulus: u128,
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<CrtBundle<Self::Item>>> {
        let mods = util::factor(modulus);
        let nmods = mods.len();
        let xs = values
            .iter()
            .flat_map(|x| util::crt(*x, &mods))
            .collect::<Vec<_>>();
        let qs = (0..values.len())
            .flat_map(|_| mods.clone())
            .collect::<Vec<_>>();
        let mut wires = self.encode_many(&xs, &qs, channel)?;
        let buns = (0..values.len())
            .map(|_| {
                let ws = wires.drain(0..nmods).collect::<Vec<_>>();
                CrtBundle::new(ws)
            })
            .collect::<Vec<_>>();
        Ok(buns)
    }

    /// Receive many CRT input bundles.
    fn crt_receive_many(
        &mut self,
        n: usize,
        modulus: u128,
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<CrtBundle<Self::Item>>> {
        let mods = util::factor(modulus);
        let nmods = mods.len();
        let qs = (0..n).flat_map(|_| mods.clone()).collect::<Vec<_>>();
        let mut wires = self.receive_many(&qs, channel)?;
        let buns = (0..n)
            .map(|_| {
                let ws = wires.drain(0..nmods).collect::<Vec<_>>();
                CrtBundle::new(ws)
            })
            .collect::<Vec<_>>();
        Ok(buns)
    }

    /// Output a CRT bundle and interpret it mod Q.
    fn crt_output(
        &mut self,
        x: &CrtBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<u128>> {
        let q = x.composite_modulus();
        Ok(self
            .output_bundle(x, channel)?
            .map(|xs| util::crt_inv_factor(&xs, q)))
    }

    /// Output a slice of CRT bundles and interpret the outputs mod Q.
    fn crt_outputs(
        &mut self,
        xs: &[CrtBundle<Self::Item>],
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<Vec<u128>>> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            let z = self.crt_output(x, channel)?;
            zs.push(z);
        }
        Ok(zs.into_iter().collect())
    }
}
