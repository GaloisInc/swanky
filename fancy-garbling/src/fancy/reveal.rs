use super::*;
use crate::util;

/// Trait to describe Fancy objects which can reveal outputs to both parties. For many
/// simple Fancy objects in this library such as Dummy, this is simply output. For Garbler
/// and Evaluator, it is more complicated since the BMR16 protocol outputs to the
/// Evaluator only.
pub trait FancyReveal: Fancy {
    /// Reveal the contents of `x` to all parties.
    fn reveal(&mut self, x: &Self::Item) -> Result<u16, Self::Error>;

    /// Reveal a slice of items to all parties.
    fn reveal_many(&mut self, xs: &[Self::Item]) -> Result<Vec<u16>, Self::Error> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            zs.push(self.reveal(x)?);
        }
        Ok(zs)
    }

    /// Reveal a bundle to all parties.
    fn reveal_bundle(&mut self, x: &Bundle<Self::Item>) -> Result<Vec<u16>, Self::Error> {
        self.reveal_many(x.wires())
    }

    /// Reveal many bundles to all parties.
    fn reveal_many_bundles(
        &mut self,
        xs: &[Bundle<Self::Item>],
    ) -> Result<Vec<Vec<u16>>, Self::Error> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            zs.push(self.reveal_bundle(x)?);
        }
        Ok(zs)
    }

    /// Reveal a CRT bundle to all parties.
    fn crt_reveal(&mut self, x: &CrtBundle<Self::Item>) -> Result<u128, Self::Error> {
        let q = x.composite_modulus();
        let xs = self.reveal_many(x.wires())?;
        Ok(util::crt_inv_factor(&xs, q))
    }

    /// Reveal many CRT bundles to all parties.
    fn crt_reveal_many(&mut self, xs: &[CrtBundle<Self::Item>]) -> Result<Vec<u128>, Self::Error> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            zs.push(self.crt_reveal(x)?);
        }
        Ok(zs)
    }

    /// Reveal a binary bundle to all parties.
    fn bin_reveal(&mut self, x: &BinaryBundle<Self::Item>) -> Result<u128, Self::Error> {
        let bits = self.reveal_many(x.wires())?;
        Ok(util::u128_from_bits(&bits))
    }

    /// Reveal many binary bundles to all parties.
    fn bin_reveal_many(
        &mut self,
        xs: &[BinaryBundle<Self::Item>],
    ) -> Result<Vec<u128>, Self::Error> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            zs.push(self.bin_reveal(x)?);
        }
        Ok(zs)
    }
}
