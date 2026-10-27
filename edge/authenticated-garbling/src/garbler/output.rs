use fancy_traits::{Fancy, FancyOutput};
use swanky_authenticated_bits::authshares::AuthShareGenerator;
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_field_binary::F2;

use crate::wire::OfflineWire;

/// The garbler's output phase.
///
/// This phase follows the [`crate::GarblerValidator`] phase and is used to
/// derive the output values of the computation using the [`FancyOutput`]
/// interface.
pub struct GarblerOutput {}

impl GarblerOutput {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

impl Fancy for GarblerOutput {
    type Item = OfflineWire;
}

impl FancyOutput<F2> for GarblerOutput {
    fn output(&mut self, x: &Self::Item, channel: &mut Channel) -> Result<Option<F2>> {
        Ok(self
            .outputs(core::slice::from_ref(x), channel)?
            .map(|xs| xs[0]))
    }

    fn outputs(&mut self, x: &[Self::Item], channel: &mut Channel) -> Result<Option<Vec<F2>>> {
        let auth_shares = x.iter().map(|wire| wire.auth_share()).collect::<Vec<_>>();
        AuthShareGenerator::open_my_shares(&auth_shares, channel)?;
        Ok(None)
    }
}
