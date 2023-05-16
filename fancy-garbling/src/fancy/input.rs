use super::*;
use crate::util;
use itertools::Itertools;

/// Convenience functions for encoding input to Fancy objects.
pub trait FancyInput {
    /// The type that this Fancy object operates over.
    type Item: Clone + HasModulus;

    /// The type of error that this Fancy object emits.
    type Error: From<FancyError>;

    ////////////////////////////////////////////////////////////////////////////////
    // required methods

    /// Encode many values where the actual input is known.
    ///
    /// When writing a garbler, the return value must correspond to the zero
    /// wire label.
    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
    ) -> Result<Vec<Self::Item>, Self::Error>;

    /// Receive many values where the input is not known.
    fn receive_many(&mut self, moduli: &[u16]) -> Result<Vec<Self::Item>, Self::Error>;

    ////////////////////////////////////////////////////////////////////////////////
    // optional methods

    /// Encode a single value.
    ///
    /// When writing a garbler, the return value must correspond to the zero
    /// wire label.
    fn encode(&mut self, value: u16, modulus: u16) -> Result<Self::Item, Self::Error> {
        let mut xs = self.encode_many(&[value], &[modulus])?;
        Ok(xs.remove(0))
    }

    /// Receive a single value.
    fn receive(&mut self, modulus: u16) -> Result<Self::Item, Self::Error> {
        let mut xs = self.receive_many(&[modulus])?;
        Ok(xs.remove(0))
    }

    /// Encode a bundle.
    fn encode_bundle(
        &mut self,
        values: &[u16],
        moduli: &[u16],
    ) -> Result<Bundle<Self::Item>, Self::Error> {
        self.encode_many(values, moduli).map(Bundle::new)
    }

    /// Receive a bundle.
    fn receive_bundle(&mut self, moduli: &[u16]) -> Result<Bundle<Self::Item>, Self::Error> {
        self.receive_many(moduli).map(Bundle::new)
    }

    /// Encode many input bundles.
    fn encode_bundles(
        &mut self,
        values: &[Vec<u16>],
        moduli: &[Vec<u16>],
    ) -> Result<Vec<Bundle<Self::Item>>, Self::Error> {
        let qs = moduli.iter().flatten().cloned().collect_vec();
        let xs = values.iter().flatten().cloned().collect_vec();
        if xs.len() != qs.len() {
            return Err(
                FancyError::InvalidArg("unequal number of values and moduli".to_string()).into(),
            );
        }
        let mut wires = self.encode_many(&xs, &qs)?;
        let buns = moduli
            .iter()
            .map(|qs| {
                let ws = wires.drain(0..qs.len()).collect_vec();
                Bundle::new(ws)
            })
            .collect_vec();
        Ok(buns)
    }

    /// Receive many input bundles.
    fn receive_many_bundles(
        &mut self,
        moduli: &[Vec<u16>],
    ) -> Result<Vec<Bundle<Self::Item>>, Self::Error> {
        let qs = moduli.iter().flatten().cloned().collect_vec();
        let mut wires = self.receive_many(&qs)?;
        let buns = moduli
            .iter()
            .map(|qs| {
                let ws = wires.drain(0..qs.len()).collect_vec();
                Bundle::new(ws)
            })
            .collect_vec();
        Ok(buns)
    }

    /// Encode a CRT input bundle.
    fn crt_encode(
        &mut self,
        value: u128,
        modulus: u128,
    ) -> Result<CrtBundle<Self::Item>, Self::Error> {
        let qs = util::factor(modulus);
        let xs = util::crt(value, &qs);
        self.encode_bundle(&xs, &qs).map(CrtBundle::from)
    }

    /// Receive an CRT input bundle.
    fn crt_receive(&mut self, modulus: u128) -> Result<CrtBundle<Self::Item>, Self::Error> {
        let qs = util::factor(modulus);
        self.receive_bundle(&qs).map(CrtBundle::from)
    }

    /// Encode many CRT input bundles.
    fn crt_encode_many(
        &mut self,
        values: &[u128],
        modulus: u128,
    ) -> Result<Vec<CrtBundle<Self::Item>>, Self::Error> {
        let mods = util::factor(modulus);
        let nmods = mods.len();
        let xs = values
            .iter()
            .flat_map(|x| util::crt(*x, &mods))
            .collect_vec();
        let qs = itertools::repeat_n(mods, values.len())
            .flatten()
            .collect_vec();
        let mut wires = self.encode_many(&xs, &qs)?;
        let buns = (0..values.len())
            .map(|_| {
                let ws = wires.drain(0..nmods).collect_vec();
                CrtBundle::new(ws)
            })
            .collect_vec();
        Ok(buns)
    }

    /// Receive many CRT input bundles.
    fn crt_receive_many(
        &mut self,
        n: usize,
        modulus: u128,
    ) -> Result<Vec<CrtBundle<Self::Item>>, Self::Error> {
        let mods = util::factor(modulus);
        let nmods = mods.len();
        let qs = itertools::repeat_n(mods, n).flatten().collect_vec();
        let mut wires = self.receive_many(&qs)?;
        let buns = (0..n)
            .map(|_| {
                let ws = wires.drain(0..nmods).collect_vec();
                CrtBundle::new(ws)
            })
            .collect_vec();
        Ok(buns)
    }

    /// Encode a binary input bundle.
    fn bin_encode(
        &mut self,
        value: u128,
        nbits: usize,
    ) -> Result<BinaryBundle<Self::Item>, Self::Error> {
        let xs = util::u128_to_bits(value, nbits);
        self.encode_bundle(&xs, &vec![2; nbits])
            .map(BinaryBundle::from)
    }

    /// Receive an binary input bundle.
    fn bin_receive(&mut self, nbits: usize) -> Result<BinaryBundle<Self::Item>, Self::Error> {
        self.receive_bundle(&vec![2; nbits]).map(BinaryBundle::from)
    }

    /// Encode many binary input bundles.
    fn bin_encode_many(
        &mut self,
        values: &[u128],
        nbits: usize,
    ) -> Result<Vec<BinaryBundle<Self::Item>>, Self::Error> {
        let xs = values
            .iter()
            .flat_map(|x| util::u128_to_bits(*x, nbits))
            .collect_vec();
        let mut wires = self.encode_many(&xs, &vec![2; values.len() * nbits])?;
        let buns = (0..values.len())
            .map(|_| {
                let ws = wires.drain(0..nbits).collect_vec();
                BinaryBundle::new(ws)
            })
            .collect_vec();
        Ok(buns)
    }

    /// Receive many binary input bundles.
    fn bin_receive_many(
        &mut self,
        ninputs: usize,
        nbits: usize,
    ) -> Result<Vec<BinaryBundle<Self::Item>>, Self::Error> {
        let mut wires = self.receive_many(&vec![2; ninputs * nbits])?;
        let buns = (0..ninputs)
            .map(|_| {
                let ws = wires.drain(0..nbits).collect_vec();
                BinaryBundle::new(ws)
            })
            .collect_vec();
        Ok(buns)
    }
}
