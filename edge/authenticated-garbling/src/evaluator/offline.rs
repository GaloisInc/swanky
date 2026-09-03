use crate::{EvaluatorOnline, WirePreProcessor, preprocesser::f_preprocessing, ps::PartyEvaluator};
use fancy_analyzer::CircuitAnalyzer;
use fancy_traits::CircuitInputMapper;
use rand::CryptoRng;
use swanky_authenticated_bits::{and_triples::AndTripleGenerator, authshares::AuthShare};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result, WrapErr};
use swanky_field_binary::F2BitDeserializer;
use swanky_serialization::SequenceDeserializer;
use vectoreyes::U8x16;

/// The evaluator's offline phase.
///
/// In the offline phase, the evaluator generates the necessary [`AuthShare`]s
/// and receives the garbled gates $`G_{\gamma, 0}, G_{\gamma, 1}`$ alongside
/// selection bits $`b_\gamma`$.
///
/// [`EvaluatorOffline::initialize`] sets up the [`AuthShare`]s. This involves
/// communication with the garbler.
///
/// [`EvaluatorOffline::finalize`] receives the garbled gates and selection bits
/// from the garbler, and returns a [`EvaluatorOnline`] for the next phase of
/// processing.
pub struct EvaluatorOffline<'a, C> {
    // The circuit to evaluate.
    circuit: &'a C,
    // The evaluator's Δ, used to validate the authenticated shares and AND
    // triples.
    delta: U8x16,
    // A vector of authenticated shares, one per input wire and AND gate output.
    // Corresponds to〈r_w, s_w〉from the paper.
    auth_shares: Vec<AuthShare<PartyEvaluator>>,
    // A vector of fixed authenticated shares for AND gate wires. Each share is
    // set such that it is equal to the AND of the incoming wire shares.
    // Corresponds to〈r_w^*, s_w^*〉from the paper.
    and_auth_shares: Vec<AuthShare<PartyEvaluator>>,
}

impl<'a, C> EvaluatorOffline<'a, C>
where
    C: CircuitInputMapper<CircuitAnalyzer> + CircuitInputMapper<WirePreProcessor<PartyEvaluator>>,
{
    /// Initialize a [`EvaluatorOffline`] object for the given circuit.
    pub fn initialize<RNG: CryptoRng>(
        circuit: &'a C,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> Result<Self> {
        let delta = AndTripleGenerator::<PartyEvaluator>::generate_valid_delta(rng);

        let mut and_generator = AndTripleGenerator::new_with_delta(delta, channel, rng)?;
        let (auth_shares, and_auth_shares) =
            f_preprocessing(circuit, &mut and_generator, channel, rng)?;
        Ok(Self {
            circuit,
            delta,
            auth_shares,
            and_auth_shares,
        })
    }
}

impl<'a, C> EvaluatorOffline<'a, C> {
    /// Receive the offline material from the garbler and return an
    /// [`EvaluatorOnline`] object for online processing.
    pub fn finalize(self, channel: &mut Channel) -> Result<EvaluatorOnline<'a, C>> {
        let nands = self.and_auth_shares.len();
        // Receive the LSBs of the zero-wirelabels of the output wires of the
        // AND gates.
        let mut bit_ser: F2BitDeserializer = SequenceDeserializer::new(channel.as_std_io())
            .wrap_err(
                ErrorKind::InitializationError,
                "Failed to create sequence deserializer.",
            )?;
        let gate_bits = bit_ser.read_vector(channel.as_std_io(), nands).wrap_err(
            ErrorKind::SerializationError,
            "Failed to read serialized bits.",
        )?;
        // Receive the garbled gates.
        let gates = (0..nands)
            .map(|_| {
                let g0: U8x16 = channel.read()?;
                let g1: U8x16 = channel.read()?;
                Ok((g0, g1))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(EvaluatorOnline::new(
            self.circuit,
            self.delta,
            self.auth_shares,
            self.and_auth_shares,
            gates,
            gate_bits,
        ))
    }
}
