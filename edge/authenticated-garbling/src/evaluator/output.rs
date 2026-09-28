use crate::EvaluatorWire;
use fancy_traits::{Fancy, FancyOutput};
use swanky_authenticated_bits::authshares::AuthShareGenerator;
use swanky_channel::Channel;
use swanky_error::Result;
use vectoreyes::U8x16;

/// The evaluator's output phase.
///
/// This phase follows the [`crate::EvaluatorValidator`] phase and is used to
/// derive the output values of the computation using the [`FancyOutput`]
/// interface.
pub struct EvaluatorOutput {
    delta: U8x16,
}

impl EvaluatorOutput {
    pub(crate) fn new(delta: U8x16) -> Self {
        Self { delta }
    }
}

impl Fancy for EvaluatorOutput {
    type Item = EvaluatorWire;
}

impl FancyOutput for EvaluatorOutput {
    fn output(&mut self, x: &Self::Item, channel: &mut Channel) -> Result<Option<u16>> {
        Ok(self
            .outputs(core::slice::from_ref(x), channel)?
            .map(|xs| xs[0]))
    }

    fn outputs(&mut self, x: &[Self::Item], channel: &mut Channel) -> Result<Option<Vec<u16>>> {
        let auth_shares = x.iter().map(|wire| wire.auth_share()).collect::<Vec<_>>();
        let mut masks = Vec::with_capacity(x.len());
        AuthShareGenerator::open_their_shares_with_delta(
            &auth_shares,
            self.delta,
            &mut masks,
            channel,
        )?;
        let outputs = masks
            .into_iter()
            .zip(x)
            .map(|(mask, out)| (mask + out.masked_value() + out.auth_share().bit()).into())
            .collect::<Vec<_>>();
        Ok(Some(outputs))
    }
}
