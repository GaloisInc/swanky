use crate::{CrtBundle, util::factor};
use fancy_traits::{Circuit, FancyConstant};
use swanky_channel::Channel;
use swanky_error::Result;

/// Arithmetic constant.
///
/// For `(value, modulus)`, return a [`CrtBundle`] containing `value` in its CRT
/// representation.
pub struct Constant {
    xs: Vec<u16>,
    moduli: Vec<u16>,
}

impl Constant {
    /// Create a new [`Constant`] circuit for `value % modulus`.
    pub fn new(value: u128, modulus: u128) -> Self {
        let moduli = factor(modulus);
        let xs = moduli
            .iter()
            .map(|&p| (value % p as u128) as u16)
            .collect::<Vec<_>>();
        Self { xs, moduli }
    }
}

impl<F: FancyConstant> Circuit<F> for Constant {
    type Input = ();
    type Output = CrtBundle<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        _: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let constants = self
            .xs
            .iter()
            .zip(self.moduli.iter())
            .map(|(&x, &p)| backend.constant(x, p, channel))
            .collect::<Result<_>>()?;
        Ok(CrtBundle::new(constants))
    }
}
