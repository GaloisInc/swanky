use crate::{
    fancy::bundle::{Bundle, BundleGadgets},
    util::{self, u128_from_bits},
};
use fancy_plaintext::{Dummy, DummyVal};
use fancy_traits::{FancyBinary, FancyEncode, FancyOutput};
use std::ops::{Deref, DerefMut};
use swanky_channel::Channel;

/// Bundle which is explicitly binary representation.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BinaryBundle<W>(Bundle<W>);

impl<W> BinaryBundle<W> {
    /// Create a new binary bundle from a vector of wires.
    pub fn new(ws: Vec<W>) -> BinaryBundle<W> {
        BinaryBundle(Bundle::new(ws))
    }
}

impl From<(u128, usize)> for BinaryBundle<DummyVal> {
    /// Generate a new [`BinaryBundle`] of `value.0` containing `value.1` bits.
    fn from(value: (u128, usize)) -> Self {
        let mut dummy = Dummy::new();
        Channel::with(std::io::empty(), |channel| {
            dummy.bin_encode(value.0, value.1, channel)
        })
        .unwrap()
    }
}

impl From<BinaryBundle<DummyVal>> for u128 {
    fn from(value: BinaryBundle<DummyVal>) -> Self {
        let bin = value.wires().iter().map(|w| w.val()).collect::<Vec<_>>();
        u128_from_bits(&bin)
    }
}

impl<W> Deref for BinaryBundle<W> {
    type Target = Bundle<W>;

    fn deref(&self) -> &Bundle<W> {
        &self.0
    }
}

impl<W> DerefMut for BinaryBundle<W> {
    fn deref_mut(&mut self) -> &mut Bundle<W> {
        &mut self.0
    }
}

impl<F: FancyBinary + FancyEncode + FancyOutput> BinaryGadgets for F {}

/// Extension trait for `Fancy` providing gadgets that operate over bundles of mod2 wires.
pub trait BinaryGadgets: BundleGadgets + FancyEncode {
    /// Encode a binary input bundle.
    fn bin_encode(
        &mut self,
        value: u128,
        nbits: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        let xs = util::u128_to_bits(value, nbits);
        self.encode_many(&xs, &vec![2; nbits], channel)
            .map(BinaryBundle::new)
    }

    /// Receive an binary input bundle.
    fn bin_receive(
        &mut self,
        nbits: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<BinaryBundle<Self::Item>> {
        self.receive_many(&vec![2; nbits], channel)
            .map(BinaryBundle::new)
    }

    /// Encode many binary input bundles.
    fn bin_encode_many(
        &mut self,
        values: &[u128],
        nbits: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<BinaryBundle<Self::Item>>> {
        let xs = values
            .iter()
            .flat_map(|x| util::u128_to_bits(*x, nbits))
            .collect::<Vec<_>>();
        let mut wires = self.encode_many(&xs, &vec![2; values.len() * nbits], channel)?;
        let buns = (0..values.len())
            .map(|_| {
                let ws = wires.drain(0..nbits).collect::<Vec<_>>();
                BinaryBundle::new(ws)
            })
            .collect::<Vec<_>>();
        Ok(buns)
    }

    /// Receive many binary input bundles.
    fn bin_receive_many(
        &mut self,
        ninputs: usize,
        nbits: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<BinaryBundle<Self::Item>>> {
        let mut wires = self.receive_many(&vec![2; ninputs * nbits], channel)?;
        let buns = (0..ninputs)
            .map(|_| {
                let ws = wires.drain(0..nbits).collect::<Vec<_>>();
                BinaryBundle::new(ws)
            })
            .collect::<Vec<_>>();
        Ok(buns)
    }

    /// Output a binary bundle and interpret the result as a `u128`.
    fn bin_output(
        &mut self,
        x: &BinaryBundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<u128>> {
        Ok(self
            .output_bundle(x, channel)?
            .map(|bs| util::u128_from_bits(&bs)))
    }

    /// Output a slice of binary bundles and interpret the results as a `u128`.
    fn bin_outputs(
        &mut self,
        xs: &[BinaryBundle<Self::Item>],
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<Vec<u128>>> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            let z = self.bin_output(x, channel)?;
            zs.push(z);
        }
        Ok(zs.into_iter().collect())
    }
}
