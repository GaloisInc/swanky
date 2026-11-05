use crate::{FancyConstant, FancyEncode, FancyOutput, FancyReceive};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;

/// A fixed-length bundle of binary wires.
///
/// Wires are represented in least-significant-bit-first order.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct BinaryBundle<W, const N: usize>([W; N]);

impl<W, const N: usize> BinaryBundle<W, N> {
    /// Create a new [`BinaryBundle`] from an array of wires.
    pub fn new(ws: [W; N]) -> Self {
        Self(ws)
    }

    /// Create a new [`BinaryBundle`] for a constant value.
    pub fn constant<F: FancyConstant<F2, Item = W>>(backend: &mut F, value: u128) -> Self {
        let xs = u128_to_bits::<N>(value);
        BinaryBundle::new(xs.map(|x| backend.constant(x)))
    }

    /// The internal array of wires contained in the [`BinaryBundle`].
    pub fn wires(&self) -> &[W; N] {
        &self.0
    }

    /// In place reversal of the wires in the [`BinaryBundle`].
    pub fn reverse(&mut self) {
        self.0.reverse();
    }

    /// Set the `i`th wire in the [`BinaryBundle`] to value.
    ///
    /// # Panics
    /// Panics if `i >= N`.
    pub fn set(&mut self, value: W, i: usize) {
        assert!(i < N);
        self.0[i] = value;
    }
}

/// Convert a `u128` into a vector of `N` bits.
///
/// # Panics
/// Panics if `N > 128`.
pub fn u128_to_bits<const N: usize>(x: u128) -> [F2; N] {
    assert!(N <= 128, "bitwidth too large: {N} > 128");
    core::array::from_fn(|i| F2::from(((x >> i) & 1) != 0))
}

/// Convert a slice of bits into a `u128`.
///
/// # Panics
/// Panics if the slice length is greater than 128.
pub fn u128_from_bits(bits: &[F2]) -> u128 {
    assert!(
        bits.len() <= 128,
        "bitwidth too large: {} > 128",
        bits.len()
    );
    let mut x = 0;
    for (i, bit) in bits.iter().enumerate() {
        x += (u16::from(*bit) as u128) << i;
    }
    x
}

impl<F: FancyEncode<F2>> BinaryEncode for F {}
impl<F: FancyReceive<F2>> BinaryReceive for F {}
impl<F: FancyOutput<F2>> BinaryOutput for F {}

/// Extension trait for [`crate::Fancy`] providing [`FancyEncode`] operations
/// over [`BinaryBundle`]s.
pub trait BinaryEncode: FancyEncode<F2> {
    /// Encode a `u128` as a [`BinaryBundle`].
    fn bin_encode<const N: usize>(
        &mut self,
        value: u128,
        channel: &mut Channel,
    ) -> Result<BinaryBundle<Self::Item, N>> {
        let xs = u128_to_bits::<N>(value);
        let encoded = self.encode_many(&xs, channel)?;
        Ok(BinaryBundle::new(
            encoded.try_into().expect("vector should be of length `N`"),
        ))
    }

    /// Encode a slice of `u128`s as a vector of [`BinaryBundle`]s.
    fn bin_encode_many<const N: usize>(
        &mut self,
        values: &[u128],
        channel: &mut Channel,
    ) -> Result<Vec<BinaryBundle<Self::Item, N>>> {
        let xs = values
            .iter()
            .flat_map(|x| u128_to_bits::<N>(*x))
            .collect::<Vec<_>>();
        let wires = self.encode_many(&xs, channel)?;
        Ok(wires
            .as_chunks::<N>()
            .0
            .iter()
            .map(|chunk| {
                BinaryBundle::new(
                    chunk
                        .to_vec()
                        .try_into()
                        .expect("vector should be of length `N`"),
                )
            })
            .collect())
    }
}

/// Extension trait for [`crate::Fancy`] providing [`FancyReceive`] operations
/// over [`BinaryBundle`]s.
pub trait BinaryReceive: FancyReceive<F2> {
    /// Receive a [`BinaryBundle`].
    fn bin_receive<const N: usize>(
        &mut self,
        channel: &mut Channel,
    ) -> Result<BinaryBundle<Self::Item, N>> {
        let wires = self.receive_many(N, channel)?;
        Ok(BinaryBundle::new(
            wires.try_into().expect("vector should be of length `N`"),
        ))
    }

    /// Receive many [`BinaryBundle`]s.
    fn bin_receive_many<const N: usize>(
        &mut self,
        ninputs: usize,
        channel: &mut Channel,
    ) -> Result<Vec<BinaryBundle<Self::Item, N>>> {
        let wires = self.receive_many(ninputs * N, channel)?;
        Ok(wires
            .as_chunks::<N>()
            .0
            .iter()
            .map(|chunk| {
                BinaryBundle::new(
                    chunk
                        .to_vec()
                        .try_into()
                        .expect("vector should be of length `N`"),
                )
            })
            .collect())
    }
}

/// Extension trait for [`crate::Fancy`] providing [`FancyOutput`] operations
/// over [`BinaryBundle`]s.
pub trait BinaryOutput: FancyOutput<F2> {
    /// Output a [`BinaryBundle`] as a `u128`.
    fn bin_output<const N: usize>(
        &mut self,
        x: &BinaryBundle<Self::Item, N>,
        channel: &mut Channel,
    ) -> Result<Option<u128>> {
        let bits =
            x.0.iter()
                .map(|wire| self.output(wire, channel))
                .collect::<Result<Option<Vec<_>>>>()?;
        Ok(bits.map(|bits| u128_from_bits(&bits)))
    }

    /// Output a slice of [`BinaryBundle`]s as a vector of `u128`s.
    fn bin_outputs<const N: usize>(
        &mut self,
        xs: &[BinaryBundle<Self::Item, N>],
        channel: &mut Channel,
    ) -> Result<Option<Vec<u128>>> {
        xs.iter()
            .map(|x| self.bin_output(x, channel))
            .collect::<Result<Option<Vec<_>>>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngExt, rng};

    #[test]
    fn u128_to_bits_conversion_works() {
        let mut rng = rng();
        for _ in 0..128 {
            let x = rng.random::<u128>();
            assert_eq!(u128_from_bits(&u128_to_bits::<128>(x)), x);
        }
    }
}
