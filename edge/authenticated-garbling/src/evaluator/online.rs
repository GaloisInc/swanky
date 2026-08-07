use fancy_garbling::{WireLabel, WireMod2};
use fancy_traits::{
    CircuitInputMapper, CircuitOutputMapper, Fancy, FancyBinary, FancyBinaryConstant, FancyEncode,
};
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result, WrapErr};
use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F2BitSerializer, F128b};
use swanky_serialization::SequenceSerializer;
use vectoreyes::U8x16;

use crate::{
    EvaluatorWire, evaluator::EvaluatorValidator, ps::PartyEvaluator, vec_wrapper::VecWrapper,
};

/// The evaluator's online phase.
///
/// The online phase supports encoding and receiving inputs through
/// [`FancyEncode`] and full circuit evaluation for circuits implementing
/// [`FancyBinary`].
pub struct EvaluatorOnline<'a, C> {
    // The circuit to evaluate.
    circuit: &'a C,
    // The evaluator's Δ, used to validate the authenticated shares and AND
    // triples.
    delta: U8x16,
    /// A wirelabel denoting one. Used to make negations and constant 1 gates free.
    one: WireMod2,
    // The index of the current AND gate. Used as the tweak when hashing
    // wirelabels in the AND gate garbling.
    and_gate_index: usize,
    // A vector of authenticated shares, one per input wire and AND gate output.
    // Corresponds to〈r_w, s_w〉from the paper.
    auth_shares: VecWrapper<AuthShare<PartyEvaluator>>,
    // A vector of fixed authenticated shares for AND gate wires. Each share is
    // set such that it is equal to the AND of the incoming wire shares.
    // Corresponds to〈r_w^*, s_w^*〉from the paper.
    and_auth_shares: VecWrapper<AuthShare<PartyEvaluator>>,
    // The masked wire values are used during the
    // finalization/validation stage.
    lc_values: Vec<F2>,
    // A vector that stores the Evaluator's validation shares. Contrary to the
    // Garbler, the Evalutor can compute these shares during evaluation.
    validation_shares: Vec<AuthShare<PartyEvaluator>>,
    // A vector that stores the garbling gates.
    gates: VecWrapper<(U8x16, U8x16)>,
    // A vector that stores the garbling gate bits.
    gate_bits: VecWrapper<F2>,
}

impl<'a, C> EvaluatorOnline<'a, C> {
    pub(crate) fn new(
        circuit: &'a C,
        delta: U8x16,
        auth_shares: Vec<AuthShare<PartyEvaluator>>,
        and_auth_shares: Vec<AuthShare<PartyEvaluator>>,
        gates: Vec<(U8x16, U8x16)>,
        gate_bits: Vec<F2>,
    ) -> Self {
        let num_and_gates = and_auth_shares.len();
        // The constant one wirelabel is set to the value `1`.
        // TODO: Make `const` once `From` is const-compatible.
        let one = WireMod2::from_repr(U8x16::from(F128b::ONE), 2);
        Self {
            circuit,
            delta,
            one,
            and_gate_index: 0,
            auth_shares: VecWrapper::new(auth_shares),
            and_auth_shares: VecWrapper::new(and_auth_shares),
            lc_values: Vec::with_capacity(num_and_gates),
            validation_shares: Vec::with_capacity(num_and_gates),
            gates: VecWrapper::new(gates),
            gate_bits: VecWrapper::new(gate_bits),
        }
    }

    /// Receive wirelabel `L_w` from the garbler, where `w` represents the
    /// masked value of the wire.
    ///
    /// This corresponds to pieces of Steps 3 and 4 in Figure 3 of the paper.
    fn receive_wirelabels(
        &mut self,
        masked_values: Vec<F2>,
        auth_shares: Vec<AuthShare<PartyEvaluator>>,
        channel: &mut Channel,
    ) -> Result<Vec<EvaluatorWire>> {
        let mut wires: Vec<EvaluatorWire> = Vec::with_capacity(masked_values.len());
        for (masked_value, auth_share) in masked_values.into_iter().zip(auth_shares) {
            // The Evaluator retrieves the wire labels for their own input
            let wire_label = WireMod2::from_repr(channel.read()?, 2);
            // The Evaluator constructs authenticated values for all their input wires
            wires.push(EvaluatorWire::new(masked_value, wire_label, auth_share));
        }
        Ok(wires)
    }

    /// Finalize the online phase of the computation.
    ///
    /// This involves sending the masked values $`\hat{z}_w`$ to the garbler.
    pub fn finalize(self, channel: &mut Channel) -> Result<EvaluatorValidator> {
        let bit_ser: F2BitSerializer = SequenceSerializer::new(&mut channel.as_std_io()).wrap_err(
            ErrorKind::InitializationError,
            "Failed to initialize sequence serializer.",
        )?;
        bit_ser
            .write_vec(channel.as_std_io(), &self.lc_values)
            .wrap_err(
                ErrorKind::SerializationError,
                "Failed to write serialized bits.",
            )?;

        Ok(EvaluatorValidator::new(self.delta, self.validation_shares))
    }

    fn next_and_gate_index(&mut self) -> usize {
        let current = self.and_gate_index;
        self.and_gate_index += 1;
        current
    }
}

impl<'a, C> EvaluatorOnline<'a, C>
where
    C: CircuitInputMapper<Self> + CircuitOutputMapper<Self>,
{
    /// Run the circuit on the provided inputs, returning the outputs as a flat
    /// vector.
    pub fn execute(mut self, inputs: Vec<EvaluatorWire>) -> Result<(Vec<EvaluatorWire>, Self)> {
        let inputs = self.circuit.map(inputs);
        let output = Channel::with(std::io::empty(), |channel| {
            self.circuit.execute(&mut self, inputs, channel)
        })?;
        Ok((C::flatten(output), self))
    }
}

impl<'a, C> Fancy for EvaluatorOnline<'a, C> {
    type Item = EvaluatorWire;
}

impl FancyBinaryConstant for EvaluatorOnline {
    fn constant(&mut self, x: bool) -> Self::Item {
        let constant = F2::from(x);
        let share = AuthShareGenerator::constant_with_delta(F2::ZERO, self.delta);

        let wirelabel = if constant == F2::ONE {
            self.one
        } else {
            Default::default()
        };

        EvaluatorWire::new(constant, wirelabel, share)
    }
}

impl<'a, C> FancyBinary for EvaluatorOnline<'a, C> {
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        EvaluatorWire::new(
            x.masked_value() + F2::ONE,
            x.wire_label() + self.one,
            x.auth_share(),
        )
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        EvaluatorWire::new(
            x.masked_value() + y.masked_value(),
            x.wire_label() + y.wire_label(),
            x.auth_share() ^ y.auth_share(),
        )
    }

    fn and(&mut self, la: &Self::Item, lb: &Self::Item, _: &mut Channel) -> Result<Self::Item> {
        // This index is called γ in the paper
        let index = self.next_and_gate_index();
        // This is the current wire's authenticated share
        let lc_share = self.auth_shares.next();
        // This is the current wire's authenticated triple
        let lc_triple = self.and_auth_shares.next();

        // This is the MAC associated with the current wire's authenticated share: M[s_γ]
        let mac_share = lc_share.mac();
        // This is the MAC associated with the current wire's authenticated triple: M[s*_γ]
        let mac_triple = lc_triple.mac();

        let (gate_c0, gate_c1) = self.gates.next();
        let bit_c = self.gate_bits.next();

        // This is the value: Gate_0 = Gate_{γ,0} + M[s_β]
        let gate0 = gate_c0 ^ lb.auth_share().mac();
        // This is the value: Gate_1 = Gate_{γ,1} + M[s_α]
        let gate1 = gate_c1 ^ la.auth_share().mac();

        // This is the value H(L_{α, z_α + λ_α}, γ)
        let h_la = la.wire_label().hash(index as u128);
        // This is the value H(L_{β, z_β + λ_β}, γ)
        let h_lb = lb.wire_label().hash(index as u128);

        // z'α := z_α + λ_α, where z_α is the actual wire value of the input
        // wire with label L_α and λ_α is the mask of that value
        let la_value = la.masked_value();
        // The Evaluator's authenticated share of λ_α
        let la_lambda = la.auth_share();
        // z'β := z_β + λ_β, where z_β is the actual wire value of the input
        // wire with label L_β and λ_β is the mask of that value
        let lb_value = lb.masked_value();
        // The Evaluator's authenticated share of λ_β
        let lb_lambda = lb.auth_share();

        // This is the value (z_α + λ_α)Gate_0
        let gate0_muxed = U8x16::from(la_value * F128b::from(gate0));
        // This is the value (z_β + λ_β)(Gate_1 + L_{α, z_α + λ_α})
        let gate1_muxed = U8x16::from(lb_value * F128b::from(gate1 ^ la.wire_label().to_repr()));

        // This the value:
        //  L_{γ, z_γ + λ_γ} := H(L_{α, z_α + λ_α}, γ) + H(L_{β, z_β + λ_β}, γ) + M[s_γ]
        //                      + M[s*_γ] + (z_α + λ_α)Gate_0 + (z_β + λ_β)(Gate_1 + L_{α, z_α + λ_α})
        let lc_label = h_la ^ h_lb ^ mac_share ^ mac_triple ^ gate0_muxed ^ gate1_muxed;

        // The current masked value of the wire is:
        // z'γ := z_γ + λ_γ := b_γ + lsb(L_{γ, z_γ + λ_γ})
        let lc_value = F128b::from(lc_label).lsb() + bit_c;

        // The Evaluator sends out the masked bit z'γ so that the Garbler
        // can locally compute their share of c_γ
        self.lc_values.push(lc_value);
        // The Evaluator computes its share of the validation bit
        // c_γ :=  (z'α ⊕ λ_α) ∧ (z'β ⊕ λ_β ) ⊕ (z'γ ⊕ λ_γ )
        //     := (z'α z'β ⊕ z'β λ_α ⊕ z'α λ_β ⊕ λ_α λ_β) ⊕ (z'γ ⊕ λ_γ )
        //     := (z'α z'β ⊕ z'γ ) ⊕ (z'β λ_α ⊕ z'α λ_β ⊕ λ*_γ ⊕ λ_γ)

        // The Evaluator first creates the constant share of (z'α z'β ⊕ z'γ )
        let share_masks =
            AuthShareGenerator::constant_with_delta(la_value * lb_value + lc_value, self.delta);
        // Then they create their share of the validation bit
        // c_γ := (z'α z'β ⊕ z'γ ) ⊕ (z'β λ_α ⊕ z'α λ_β ⊕ λ*_γ ⊕ λ_γ)
        let validation_share = share_masks
            ^ la_lambda.mul_with_const(lb_value)
            ^ lb_lambda.mul_with_const(la_value)
            ^ lc_triple
            ^ lc_share;
        self.validation_shares.push(validation_share);

        Ok(EvaluatorWire::new(
            lc_value,
            WireMod2::from_repr(lc_label, 2),
            lc_share,
        ))
    }
}

impl<'a, C> FancyEncode for EvaluatorOnline<'a, C> {
    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> Result<Vec<Self::Item>> {
        assert_eq!(values.len(), moduli.len());

        // Grab authenticated shares for each of the inputs.
        let my_auth_shares = (0..moduli.len())
            .map(|_| self.auth_shares.next())
            .collect::<Vec<_>>();

        // Open the garbler's shares `[r_w]`.
        let mut their_bits = Vec::with_capacity(moduli.len());
        AuthShareGenerator::open_their_shares_with_delta(
            &my_auth_shares,
            self.delta,
            &mut their_bits,
            channel,
        )?;

        // Compute masked values `y_w ⊕ λ_w := y_w ⊕ (s_w ⊕ r_w)`.
        let my_masked_values = their_bits
            .into_iter()
            .zip(my_auth_shares.iter().zip(values.iter()))
            .map(|(theirs, (mine, value))| {
                F2::try_from(*value).expect("Invalid value, must be boolean") + mine.bit() + theirs
            })
            .collect::<Vec<_>>();
        for masked_value in my_masked_values.iter() {
            channel.write(masked_value)?;
        }

        self.receive_wirelabels(my_masked_values, my_auth_shares, channel)
    }

    fn receive_many(&mut self, moduli: &[u16], channel: &mut Channel) -> Result<Vec<Self::Item>> {
        // Grab authenticated shares for each of the inputs.
        let my_auth_shares = (0..moduli.len())
            .map(|_i| self.auth_shares.next())
            .collect::<Vec<_>>();

        // Open the evaluator's shares `[s_w]`.
        AuthShareGenerator::open_my_shares(&my_auth_shares, channel)?;

        // Receive `x_w ⊕ λ_w` from the garbler.
        let masked_values = (0..moduli.len())
            .map(|_| channel.read::<F2>())
            .collect::<Result<Vec<_>>>()?;

        self.receive_wirelabels(masked_values, my_auth_shares, channel)
    }
}
