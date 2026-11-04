use crate::util::{self, u128_from_bits};
use fancy_plaintext::{Dummy, DummyVal};
use fancy_traits::{FancyEncode, FancyOutput, FancyReceive};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;

/// A bundle of binary wires.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BinaryBundle<W, const N: usize>([W; N]);

impl<W, const N: usize> BinaryBundle<W, N> {
    /// Create a new binary bundle from an array of wires.
    pub fn new(ws: [W; N]) -> Self {
        Self(ws)
    }

    /// The internal array of wires contained in the [`BinaryBundle`].
    pub fn wires(&self) -> &[W; N] {
        &self.0
    }

    /// In place reversal of the wires in the [`BinaryBundle`].
    pub(crate) fn reverse(&mut self) {
        self.0.reverse();
    }

    /// Set the `i`th wire in the [`BinaryBundle`] to value.
    ///
    /// # Panics
    /// Panics if `i >= N`.
    pub(crate) fn set(&mut self, value: W, i: usize) {
        assert!(i < N);
        self.0[i] = value;
    }
}

impl<const N: usize> From<u128> for BinaryBundle<DummyVal<F2>, N> {
    /// Generate a new [`BinaryBundle`] of `value % 2^N`.
    fn from(value: u128) -> Self {
        let mut dummy = Dummy::new();
        Channel::with(std::io::empty(), |channel| dummy.bin_encode(value, channel)).unwrap()
    }
}

impl<const N: usize> From<BinaryBundle<DummyVal<F2>, N>> for u128 {
    fn from(value: BinaryBundle<DummyVal<F2>, N>) -> Self {
        let bin = value.0.iter().map(|w| w.val()).collect::<Vec<_>>();
        u128_from_bits(&bin)
    }
}

impl<F: FancyEncode<F2>> BinaryEncode for F {}
impl<F: FancyReceive<F2>> BinaryReceive for F {}
impl<F: FancyOutput<F2>> BinaryOutput for F {}

/// Extension trait for `Fancy` providing encode gadgets over bundles of wires.
pub trait BinaryEncode: FancyEncode<F2> {
    /// Encode a binary input bundle.
    fn bin_encode<const N: usize>(
        &mut self,
        value: u128,
        channel: &mut Channel,
    ) -> Result<BinaryBundle<Self::Item, N>> {
        let xs = util::u128_to_bits::<N>(value);
        let encoded = self.encode_many(&xs, channel)?;
        Ok(BinaryBundle::new(
            encoded.try_into().expect("vector should be of length `N`"),
        ))
    }

    /// Encode many binary input bundles.
    fn bin_encode_many<const N: usize>(
        &mut self,
        values: &[u128],
        channel: &mut Channel,
    ) -> Result<Vec<BinaryBundle<Self::Item, N>>> {
        let xs = values
            .iter()
            .flat_map(|x| util::u128_to_bits::<N>(*x))
            .collect::<Vec<_>>();
        let mut wires = self.encode_many(&xs, channel)?;
        let buns = (0..values.len())
            .map(|_| {
                let ws = wires.drain(0..N).collect::<Vec<_>>();
                BinaryBundle::new(ws.try_into().expect("vector should be of length `N`"))
            })
            .collect::<Vec<_>>();
        Ok(buns)
    }
}

/// Extension trait for `Fancy` providing receive gadgets over bundles of wires.
pub trait BinaryReceive: FancyReceive<F2> {
    /// Receive an binary input bundle.
    fn bin_receive<const N: usize>(
        &mut self,
        channel: &mut Channel,
    ) -> Result<BinaryBundle<Self::Item, N>> {
        let wires = self.receive_many(N, channel)?;
        Ok(BinaryBundle::new(
            wires.try_into().expect("vector should be of length `N`"),
        ))
    }

    /// Receive many binary input bundles.
    fn bin_receive_many<const N: usize>(
        &mut self,
        ninputs: usize,
        channel: &mut Channel,
    ) -> Result<Vec<BinaryBundle<Self::Item, N>>> {
        let mut wires = self.receive_many(ninputs * N, channel)?;
        let buns = (0..ninputs)
            .map(|_| {
                let ws = wires.drain(0..N).collect::<Vec<_>>();
                BinaryBundle::new(ws.try_into().expect("vector should be of length `N`"))
            })
            .collect::<Vec<_>>();
        Ok(buns)
    }
}

/// Extension trait for `Fancy` providing output gadgets over bundles of wires.
pub trait BinaryOutput: FancyOutput<F2> {
    /// Output a binary bundle and interpret the result as a `u128`.
    fn bin_output<const N: usize>(
        &mut self,
        x: &BinaryBundle<Self::Item, N>,
        channel: &mut Channel,
    ) -> Result<Option<u128>> {
        let bits =
            x.0.iter()
                .map(|wire| self.output(wire, channel))
                .collect::<Result<Option<Vec<_>>>>()?;
        Ok(bits.map(|bits| util::u128_from_bits(&bits)))
    }

    /// Output a slice of binary bundles and interpret the results as a `u128`.
    fn bin_outputs<const N: usize>(
        &mut self,
        xs: &[BinaryBundle<Self::Item, N>],
        channel: &mut Channel,
    ) -> Result<Option<Vec<u128>>> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            let z = self.bin_output(x, channel)?;
            zs.push(z);
        }
        Ok(zs.into_iter().collect())
    }
}
