use crate::{
    GarblerValidator,
    ps::PartyGarbler,
    vec_wrapper::VecWrapper,
    wire::{OfflineWire, ValidatorWire},
};
use fancy_garbling::{WireLabel, WireMod2};
use fancy_traits::{Fancy, FancyEncode};
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result, WrapErr};
use swanky_field_binary::{F2, F2BitDeserializer, F128b};
use swanky_serialization::SequenceDeserializer;
use vectoreyes::U8x16;

/// The garbler's online phase.
///
/// The online phase supports encoding and receiving inputs through
/// [`FancyEncode`]. Once, inputs have been shared, [`GarblerOnline::finalize`]
/// receives the necessary masked bits from the evaluator, and returns a
/// [`GarblerValidator`] for the next phase of processing.
pub struct GarblerOnline<'a, C> {
    // The circuit to garble.
    circuit: &'a C,
    // The garbler's Δ.
    delta: WireMod2,
    // A vector of authenticated shares, one per input wire and AND gate output.
    // Corresponds to〈r_w, s_w〉from the paper.
    auth_shares: VecWrapper<AuthShare<PartyGarbler>>,
    // A vector of fixed authenticated shares for AND gate wires. Each share is
    // set such that it is equal to the AND of the incoming wire shares.
    // Corresponds to〈r_w^*, s_w^*〉from the paper.
    and_auth_shares: VecWrapper<AuthShare<PartyGarbler>>,
    // The offline wire material for the inputs.
    inputs: VecWrapper<OfflineWire>,
}

impl<'a, C> GarblerOnline<'a, C> {
    pub(crate) fn new(
        circuit: &'a C,
        delta: WireMod2,
        auth_shares: VecWrapper<AuthShare<PartyGarbler>>,
        and_auth_shares: VecWrapper<AuthShare<PartyGarbler>>,
        inputs: VecWrapper<OfflineWire>,
    ) -> Self {
        Self {
            circuit,
            delta,
            auth_shares,
            and_auth_shares,
            inputs,
        }
    }

    /// Send the wirelabel $`L_b`$ associated with the masked input value $`b`$
    /// to the evaluator and return a vector of the corresponding
    /// [`ValidatorWire`] values.
    ///
    /// This corresponds to pieces of Steps 3 and 4 in Figure 3 of the paper.
    fn encode_wirelabels(
        &mut self,
        wires: &[OfflineWire],
        masked_values: Vec<F2>,
        channel: &mut Channel,
    ) -> Result<Vec<ValidatorWire>> {
        masked_values
            .iter()
            .zip(wires.iter())
            .map(|(masked_value, wire)| {
                // Use masked values `x_w + λ_w` and zero wirelabels `L_0` to create
                // wirelabels `L_{x_w + λ_w}`, and send these to the evaluator.
                let wirelabel = wire.wirelabel()
                    + WireMod2::from_repr(
                        U8x16::from(*masked_value * F128b::from(self.delta.to_repr())),
                        2,
                    );
                channel.write(&wirelabel.to_repr())?;
                Ok(ValidatorWire::new(*masked_value, wire.auth_share()))
            })
            .collect()
    }

    pub(crate) fn delta(&self) -> U8x16 {
        self.delta.to_repr()
    }

    /// Finalize the online phase of the computation.
    ///
    /// This involves receiving the masked values $`\hat{z}_w`$ from the
    /// evaluator.
    pub fn finalize(self, channel: &mut Channel) -> Result<GarblerValidator<'a, C>> {
        let nands = self.and_auth_shares.len();
        // Receive the masked values from the Evaluator
        let mut bit_deser: F2BitDeserializer = SequenceDeserializer::new(channel.as_std_io())
            .wrap_err(
                ErrorKind::InitializationError,
                "Failed to create sequence deserializer.",
            )?;
        let lc_values = bit_deser.read_vector(channel.as_std_io(), nands).wrap_err(
            ErrorKind::SerializationError,
            "Failed to read serialized bits.",
        )?;

        let auth_shares: Vec<_> = self.auth_shares.into();
        Ok(GarblerValidator::new(
            self.circuit,
            self.delta,
            // The validator uses the non-input `AuthShare`s.
            auth_shares[self.inputs.len()..].to_vec(),
            self.and_auth_shares.into(),
            lc_values,
        ))
    }
}

impl<'a, C> Fancy for GarblerOnline<'a, C> {
    type Item = ValidatorWire;
}

impl<'a, C> FancyEncode for GarblerOnline<'a, C> {
    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> Result<Vec<Self::Item>> {
        assert_eq!(values.len(), moduli.len());

        let offline_wires = (0..moduli.len())
            .map(|_| self.inputs.next())
            .collect::<Vec<_>>();
        let my_auth_shares: Vec<AuthShare<PartyGarbler>> =
            offline_wires.iter().map(|w| w.auth_share()).collect();

        // Open the evaluator's shares `[s_w]` using these shares.
        let mut their_bits = Vec::with_capacity(values.len());
        AuthShareGenerator::open_their_shares_with_delta(
            &my_auth_shares,
            self.delta(),
            &mut their_bits,
            channel,
        )?;

        // Compute masked values `x_w ⊕ λ_w := x_w ⊕ (s_w ⊕ r_w)`.
        let my_masked_values = their_bits
            .into_iter()
            .zip(my_auth_shares.iter().zip(values.iter()))
            .map(|(theirs, (mine, value))| {
                F2::try_from(*value)
                    .wrap_err(ErrorKind::OtherError, "Invalid value, must be boolean")
                    .map(|value| theirs + mine.bit() + value)
            })
            .collect::<Result<Vec<_>>>()?;

        // Send `x_w ⊕ λ_w` to the evaluator.
        for masked_value in my_masked_values.iter() {
            channel.write(masked_value)?;
        }

        self.encode_wirelabels(&offline_wires, my_masked_values, channel)
    }

    fn receive_many(&mut self, moduli: &[u16], channel: &mut Channel) -> Result<Vec<Self::Item>> {
        let offline_wires = (0..moduli.len())
            .map(|_| self.inputs.next())
            .collect::<Vec<_>>();
        let my_auth_shares: Vec<AuthShare<PartyGarbler>> =
            offline_wires.iter().map(|w| w.auth_share()).collect();

        // Open the garbler's shares `[r_w]` using these shares.
        AuthShareGenerator::open_my_shares(&my_auth_shares, channel)?;

        // Receive `y_w ⊕ λ_w := y_w ⊕ (s_w ⊕ r_w)` from the evaluator.
        let their_masked_values = (0..moduli.len())
            .map(|_| channel.read::<F2>())
            .collect::<Result<Vec<_>>>()?;

        self.encode_wirelabels(&offline_wires, their_masked_values, channel)
    }
}
