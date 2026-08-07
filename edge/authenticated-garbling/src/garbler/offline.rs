use crate::garbler::GarblerOnline;
use crate::preprocesser::WirePreProcessor;
use crate::preprocesser::f_preprocessing;
use crate::ps::PartyGarbler;
use crate::vec_wrapper::VecWrapper;
use crate::wire::OfflineWire;
use fancy_analyzer::CircuitAnalyzer;
use fancy_garbling::{WireLabel, WireMod2};
use fancy_traits::CircuitOutputMapper;
use fancy_traits::FancyBinaryConstant;
use fancy_traits::{CircuitInputMapper, Fancy, FancyBinary};
use rand::{CryptoRng, Rng};
use swanky_authenticated_bits::and_triples::AndTripleGenerator;
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_channel::Channel;
use swanky_error::ErrorKind;
use swanky_error::Result;
use swanky_error::WrapErr;
use swanky_field::FiniteRing;
use swanky_field_binary::F2BitSerializer;
use swanky_field_binary::{F2, F128b};
use swanky_serialization::SequenceSerializer;
use vectoreyes::U8x16;

/// The garbler's offline phase.
///
/// In the offline phase, the garbler generates the necessary [`AuthShare`]s,
/// alongside the garbled gates $`G_{\gamma, 0}, G_{\gamma, 1}`$ and selection
/// bits $`b_\gamma`$ for each AND gate in the circuit.
///
/// [`GarblerOffline::initialize`] sets up the [`AuthShare`]s. This involves
/// communication with the evaluator.
///
/// [`GarblerOffline::execute`] evaluates the circuit locally, producing the
/// garbled gates and selection bits, and returning the output wires to be used
/// in the garbler's output phase.
///
/// [`GarblerOffline::finalize`] sends the garbled gates and selection bits to
/// the evaluator, and returns a [`GarblerOnline`] for the next phase of
/// processing.
pub struct GarblerOffline<'a, C> {
    // The circuit to garble.
    circuit: &'a C,
    // The garbler's Δ.
    delta: WireMod2,
    // A random wirelabel denoting zero. Used to make negations and constant one
    // gates free.
    zero: WireMod2,
    // The index of the current AND gate. Used as the tweak when hashing
    // wirelabels in the AND gate garbling.
    and_gate_index: usize,
    // Authenticated shares, one per input wire and AND gate output. Corresponds
    // to〈r_w, s_w〉from the paper.
    auth_shares: VecWrapper<AuthShare<PartyGarbler>>,
    // Authenticated shares for AND gate output wires. Each share is set such
    // that it is equal to the AND of the incoming wire shares. Corresponds
    // to〈r_w^*, s_w^*〉from the paper.
    and_auth_shares: VecWrapper<AuthShare<PartyGarbler>>,
    // The garbled AND gates.
    gates: Vec<(U8x16, U8x16)>,
    // The LSBs of the zero-wirelabels associated with AND gates output wires.
    gate_bits: Vec<F2>,
    // The input wires to the circuit.
    inputs: Vec<OfflineWire>,
}

impl<'a, C> GarblerOffline<'a, C>
where
    C: CircuitInputMapper<CircuitAnalyzer> + CircuitInputMapper<WirePreProcessor<PartyGarbler>>,
{
    /// Initialize a [`GarblerOffline`] object for the given circuit.
    pub fn initialize<RNG: CryptoRng + Rng>(
        circuit: &'a C,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> Result<Self> {
        let ninputs: usize = <C as CircuitInputMapper<CircuitAnalyzer>>::ninputs(circuit);
        let delta = AndTripleGenerator::<PartyGarbler>::generate_valid_delta(rng);
        // The constant one wirelabel is set to the value `1`, and the zero
        // wirelabel is simply the one wirelabel XORed with Δ.
        let zero = U8x16::from(F128b::ONE) ^ delta;

        let mut and_generator = AndTripleGenerator::new_with_delta(delta, channel, rng)?;
        let (auth_shares, and_auth_shares) =
            f_preprocessing(circuit, &mut and_generator, channel, rng)?;
        let nands = and_auth_shares.len();
        let mut auth_shares = VecWrapper::new(auth_shares);

        // channel.write(&one.to_repr())?;

        let inputs = (0..ninputs)
            .map(|_| OfflineWire::new(WireMod2::rand(rng, 2), auth_shares.next()))
            .collect::<Vec<_>>();

        Ok(Self {
            circuit,
            delta: WireMod2::from_repr(delta, 2),
            zero: WireMod2::from_repr(zero, 2),
            and_gate_index: 0,
            auth_shares,
            and_auth_shares: VecWrapper::new(and_auth_shares),
            gates: Vec::with_capacity(nands),
            gate_bits: Vec::with_capacity(nands),
            inputs,
        })
    }
}

impl<'a, C> GarblerOffline<'a, C>
where
    C: CircuitInputMapper<Self> + CircuitOutputMapper<Self>,
{
    /// Execute the circuit in offline mode, returning the circuit outputs.
    pub fn execute(mut self) -> Result<(Vec<OfflineWire>, Self)> {
        let inputs = CircuitInputMapper::<Self>::map(self.circuit, self.inputs.clone());
        let outputs = Channel::with(std::io::empty(), |channel| {
            self.circuit.execute(&mut self, inputs, channel)
        })?;
        Ok((C::flatten(outputs), self))
    }

    /// Send the offline material to the evaluator and return a
    /// [`GarblerOnline`] object for online processing.
    pub fn finalize(self, channel: &mut Channel) -> Result<GarblerOnline<'a, C>> {
        // The garbler sends out all the gate material that they computed offline
        let bit_ser: F2BitSerializer = SequenceSerializer::new(&mut channel.as_std_io()).wrap_err(
            ErrorKind::InitializationError,
            "Failed to initialize sequence serializer.",
        )?;
        // Send the LSB of the zero-wirelabels of the output wires of the AND gates.
        bit_ser
            .write_vec(channel.as_std_io(), &self.gate_bits)
            .wrap_err(
                ErrorKind::SerializationError,
                "Failed to write serialized bits.",
            )?;
        // Send the garbled gates.
        for (g0, g1) in self.gates.iter() {
            channel.write(g0)?;
            channel.write(g1)?;
        }
        Ok(GarblerOnline::new(
            self.circuit,
            self.delta,
            self.auth_shares,
            self.and_auth_shares,
            VecWrapper::new(self.inputs),
        ))
    }
}

impl<'a, C> GarblerOffline<'a, C> {
    fn next_and_gate_index(&mut self) -> usize {
        let current = self.and_gate_index;
        self.and_gate_index += 1;
        current
    }
}

impl<'a, C> Fancy for GarblerOffline<'a, C> {
    type Item = OfflineWire;
}

impl<'a, C> FancyBinaryConstant for GarblerOffline<'a, C> {
    fn constant(&mut self, value: bool) -> Self::Item {
        let constant = F2::from(value);
        let share = AuthShareGenerator::constant_with_delta(F2::ZERO, self.delta.to_repr());
        let wirelabel = if constant == F2::ONE {
            // `self.zero` corresponds to the zero wirelabel associated with the
            // "one" wirelabel set to `F128b::ONE`.
            self.zero
        } else {
            // Otherwise, the garbler uses the "null" wirelabel to represent zero.
            Default::default()
        };
        OfflineWire::new(wirelabel, share)
    }
}

impl<'a, C> FancyBinary for GarblerOffline<'a, C> {
    fn and(&mut self, la0: &Self::Item, lb0: &Self::Item, _: &mut Channel) -> Result<Self::Item> {
        // This index is called γ in the paper
        let index = self.next_and_gate_index();
        // This is the share for wire label L_{γ,0}
        let lc_share = self.auth_shares.next();
        // This is the and triple share for wire label L_{γ,0}
        let lc_triple = self.and_auth_shares.next();

        // Compute l1 from l0 for both inputs
        //
        // This wire label is L_{α,1} = L_{α,0} + Δ
        let la1 = la0.wirelabel() + self.delta;
        // This wire label is L_{β,1} = L_{β,0} + Δ
        let lb1 = lb0.wirelabel() + self.delta;

        // Hash l0 and l1 from both inputs and use the current index as a tweak
        //
        // This is H(L_{α,0}, γ) in the paper
        let h_la0 = la0.wirelabel().hash(index as u128);
        // This is H(L_{β,0}, γ) in the paper
        let h_lb0 = lb0.wirelabel().hash(index as u128);
        // This is H(L_{α,1}, γ) in the paper
        let h_la1 = la1.hash(index as u128);
        // This is H(L_{β,1}, γ) in the paper
        let h_lb1 = lb1.hash(index as u128);

        // Extract the share keys for the inputs, the current gate share, and the and triple
        // This is K[s_α] in the paper
        let key_a = la0.auth_share().key();
        // This is K[s_β] in the paper
        let key_b = lb0.auth_share().key();
        // This is K[s_γ] in the paper
        let key_c = lc_share.key();
        // This is K[s*_γ] in the paper
        let key_c_triple = lc_triple.key();

        // Compute Δ_rα := Δ x r_α: if r_α is 0, then this value is 0, otherwise its Δ
        let delta_bit_a = U8x16::from(la0.auth_share().bit() * F128b::from(self.delta.to_repr()));
        // Compute Δ_rβ := Δ x r_β: if r_β is 0, then this value is 0, otherwise its Δ
        let delta_bit_b = U8x16::from(lb0.auth_share().bit() * F128b::from(self.delta.to_repr()));
        // Compute Δ_rγ := Δ x r_γ: if r_γ is 0, then this value is 0, otherwise its Δ
        let delta_bit_c = U8x16::from(lc_share.bit() * F128b::from(self.delta.to_repr()));
        // Compute Δ_r*γ := Δ x r*_γ: if r*_γ is 0, then this value is 0, otherwise its Δ
        let delta_bit_c_triple = U8x16::from(lc_triple.bit() * F128b::from(self.delta.to_repr()));

        // Gate_{γ,0} = H(L_{α,0}, γ) + H(L_{α,1}, γ) + K[s_β] + Δ_rβ
        let gate0 = h_la0 ^ h_la1 ^ key_b ^ delta_bit_b;
        // Gate_{γ,1} = H(L_{β,0}, γ) + H(L_{β,1}, γ) + K[s_α] + Δ_rα + L_{α,0}
        let gate1 = h_lb0 ^ h_lb1 ^ key_a ^ delta_bit_a ^ la0.wirelabel().to_repr();
        // L_{γ,0} = H(L_{α,0}, γ) + H(L_{β,0}, γ) + K[s_γ] + Δ_rγ + K[s*_γ] + Δ_r*γ
        let lc0 = h_la0 ^ h_lb0 ^ key_c ^ delta_bit_c ^ key_c_triple ^ delta_bit_c_triple;
        // b_γ = lsb(L_{γ,0})
        let bit_c = F128b::from(lc0).lsb();

        self.gates.push((gate0, gate1));
        self.gate_bits.push(bit_c);

        Ok(OfflineWire::new(WireMod2::from_repr(lc0, 2), lc_share))
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        OfflineWire::new(
            x.wirelabel() + y.wirelabel(),
            x.auth_share() ^ y.auth_share(),
        )
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        OfflineWire::new(
            WireMod2::from_repr(x.wirelabel().to_repr() ^ self.zero.to_repr(), 2),
            x.auth_share(),
        )
    }
}
