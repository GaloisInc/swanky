use fancy_traits::{FancyOutput, HasModulus};
use swanky_channel::Channel;

/// A collection of wires, useful for the garbled gadgets defined by `BundleGadgets`.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Bundle<W>(Vec<W>);

impl<W: Clone + HasModulus> Bundle<W> {
    /// Create a new bundle from some wires.
    pub fn new(ws: Vec<W>) -> Bundle<W> {
        Bundle(ws)
    }

    /// Extract the wires from this bundle.
    pub fn wires(&self) -> &Vec<W> {
        &self.0
    }

    /// The number of wires in this bundle.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the bundle is empty or not.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Pad the Bundle with val, n times.
    pub(crate) fn pad(&mut self, val: &W, n: usize) {
        for _ in 0..n {
            self.0.push(val.clone());
        }
    }

    /// Insert a wire from the Bundle
    pub(crate) fn insert(&mut self, wire_index: usize, val: W) {
        self.0.insert(wire_index, val)
    }

    /// push a wire onto the Bundle.
    pub(crate) fn push(&mut self, val: W) {
        self.0.push(val);
    }

    /// Pop a wire from the Bundle.
    pub(crate) fn pop(&mut self) -> Option<W> {
        self.0.pop()
    }

    /// Access the underlying iterator
    pub fn iter(&self) -> std::slice::Iter<'_, W> {
        self.0.iter()
    }

    /// Reverse the wires
    pub(crate) fn reverse(&mut self) {
        self.0.reverse();
    }
}

impl<F: FancyOutput> BundleGadgets for F {}

/// Extension trait for Fancy which provides Bundle constructions which are not
/// necessarily CRT nor binary-based.
pub trait BundleGadgets: FancyOutput {
    /// Output the wires that make up a bundle.
    fn output_bundle(
        &mut self,
        x: &Bundle<Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<Vec<u16>>> {
        let ws = x.wires();
        let mut outputs = Vec::with_capacity(ws.len());
        for w in ws.iter() {
            outputs.push(self.output(w, channel)?);
        }
        Ok(outputs.into_iter().collect())
    }

    /// Output a slice of bundles.
    fn output_bundles(
        &mut self,
        xs: &[Bundle<Self::Item>],
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<Vec<Vec<u16>>>> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            let z = self.output_bundle(x, channel)?;
            zs.push(z);
        }
        Ok(zs.into_iter().collect())
    }
}
