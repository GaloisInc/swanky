use crate::{GarblerOutput, ps::PartyGarbler, vec_wrapper::VecWrapper, wire::ValidatorWire};
use fancy_garbling::{WireLabel, WireMod2};
use fancy_traits::{CircuitInputMapper, Fancy, FancyBinary, FancyBinaryConstant};
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result};
use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use vectoreyes::U8x16;

/// The garbler's validation phase.
///
/// In the validation phase, the garbler evaluates the circuit and checks that
/// the necessary validation bits are all zero.
pub struct GarblerValidator<'a, C> {
    // The circuit to validate.
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
    validation_shares: Vec<AuthShare<PartyGarbler>>,
    // A vector that stores the masked wire values received from the evaluator.
    lc_values: VecWrapper<F2>,
}

impl<'a, C> GarblerValidator<'a, C> {
    /// Create a new [`GarblerValidator`].
    pub(crate) fn new(
        circuit: &'a C,
        delta: WireMod2,
        auth_shares: Vec<AuthShare<PartyGarbler>>,
        and_auth_shares: Vec<AuthShare<PartyGarbler>>,
        lc_values: Vec<F2>,
    ) -> Self {
        Self {
            circuit,
            delta,
            auth_shares: VecWrapper::new(auth_shares),
            and_auth_shares: VecWrapper::new(and_auth_shares),
            validation_shares: Vec::new(),
            lc_values: VecWrapper::new(lc_values),
        }
    }

    fn delta(&self) -> U8x16 {
        self.delta.to_repr()
    }
}

impl<'a, C> GarblerValidator<'a, C>
where
    C: CircuitInputMapper<Self>,
{
    /// Validate the computation.
    ///
    /// This checks that all the validation bits are zero. It outputs a
    /// [`GarblerOutput`] for processing any output values.
    pub fn validate(
        mut self,
        inputs: Vec<ValidatorWire>,
        channel: &mut Channel,
    ) -> Result<GarblerOutput> {
        // Locally run the circuit to correctly construct the validation shares.
        let inputs = self.circuit.map(inputs);
        Channel::with(std::io::empty(), {
            |c| self.circuit.execute(&mut self, inputs, c)
        })?;

        let mut validation_bits = Vec::with_capacity(self.and_auth_shares.len());
        // The parties then open the share c_γ
        AuthShareGenerator::open_with_delta(
            &self.validation_shares,
            self.delta(),
            &mut validation_bits,
            channel,
        )?;

        let validation_failures: Vec<&F2> =
            validation_bits.iter().filter(|&&x| x == F2::ONE).collect();
        swanky_error::ensure!(
            validation_failures.is_empty(),
            ErrorKind::OtherError,
            "Evaluator's authentication validation check failed"
        );
        Ok(GarblerOutput::new())
    }
}

impl<'a, C> Fancy for GarblerValidator<'a, C> {
    type Item = ValidatorWire;
}

impl<'a, C> FancyBinaryConstant for GarblerValidator<'a, C> {
    fn constant(&mut self, constant: F2) -> Self::Item {
        let auth_share = AuthShareGenerator::constant_with_delta(F2::ZERO, self.delta());

        ValidatorWire::new(constant, auth_share)
    }
}

impl<'a, C> FancyBinary for GarblerValidator<'a, C> {
    fn and(&mut self, la0: &Self::Item, lb0: &Self::Item, _: &mut Channel) -> Result<Self::Item> {
        // This is the share for wire label L_{γ,0}
        let lc_share = self.auth_shares.next();
        // This is the and triple share for wire label L_{γ,0}
        let lc_triple = self.and_auth_shares.next();

        let lc_value = self.lc_values.next();
        // z'α := z_α + λ_α, where z_α is the actual wire value of the input
        // wire with label L_α and λ_α is the mask of that value
        let la_value = la0.masked_value();
        // The Garbler's authenticated share of λ_α
        let la_lambda = la0.auth_share();
        // z'β := z_β + λ_β, where z_β is the actual wire value of the input
        // wire with label L_β and λ_β is the mask of that value
        let lb_value = lb0.masked_value();
        // The Garbler's authenticated share of λ_β
        let lb_lambda = lb0.auth_share();

        // The Garbler first creates the constant share of (z'α z'β ⊕ z'γ )
        let share_masks =
            AuthShareGenerator::constant_with_delta(la_value * lb_value + lc_value, self.delta());
        // Then they create their share of the validation bit
        // c_γ := (z'α z'β ⊕ z'γ ) ⊕ (z'β λ_α ⊕ z'α λ_β ⊕ λ*_γ ⊕ λ_γ)
        self.validation_shares.push(
            share_masks
                ^ la_lambda.mul_with_const(lb_value)
                ^ lb_lambda.mul_with_const(la_value)
                ^ lc_triple
                ^ lc_share,
        );
        Ok(ValidatorWire::new(lc_value, lc_share))
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        ValidatorWire::new(
            x.masked_value() + y.masked_value(),
            x.auth_share() ^ y.auth_share(),
        )
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        ValidatorWire::new(x.masked_value() + F2::ONE, x.auth_share())
    }
}
