//! Authenticated Garbling's pre-processing functionality.
//!
//! The first step in authenticated garbling consists in pre-processing a fixed
//! circuit in order to give each party shares of wire labels. This pre-processing
//! step is one of the main reasons why authenticated garbling achieves
//! an *online* communication complexity that is "close to" its semi-honest counterpart.
//! See Figure 2 from Katz et al.[^1] for more details.
//!
//! The idea behind pre-processing is to generate random authenticated shares "per wire"[^0] that
//! are input independent and circuit dependent. These shares will later be used for both
//! authentication and garbling during the "online" phase. We consider that these shares are
//! circuit dependent because the output wires of AND gates are associated with two pairs of
//! shares:
//! (1) The regular authenticated shares
//! (2) Correlated authenticated shares that we call AND triples
//! these two pairs of AND shares are combined in the online phase to properly garble and evaluate
//! AND gates. See Figure 2 from Katz et al.[^1] for more details.
//!
//! [^0]: In practice, we only generate these shares for input wires and the output wires
//! of AND gates. The reason is that the construction preserves certain classic Garbled Circuits
//! optimizations and namely free-XORs [^1]. Recall that in free-XOR: $`L_0 \oplus L_1 = \Delta`$.
//!
//! References:
//! [^1]: J. Katz, S. Ranellucci, M. Rosulek, X. Wang. "Optimizing Authenticated
//! Garbling for Faster Secure Two-Party Computation".
//! <https://eprint.iacr.org/2018/578.pdf>

use fancy_analyzer::CircuitAnalyzer;
use fancy_traits::CircuitInputMapper;
use rand::CryptoRng;
use swanky_authenticated_bits::{and_triples::AndTripleGenerator, authshares::AuthShare};
use swanky_channel::Channel;
use swanky_party::GenericParty;

mod wire;
pub use crate::preprocesser::wire::WirePreProcessor;

/// Pre-process a circuit for authenticated garbling.
///
/// Authenticated garbling utilizes pre-computed
/// [`AndTriple`](swanky_authenticated_bits::and_triples::AndTriple)s and
/// [`AuthShare`]s in its "online" portion. This function returns the (1) wire
/// shares and (2) triple output shares for the given circuit of interest.
pub(crate) fn f_preprocessing<P: GenericParty, C, RNG: CryptoRng>(
    circuit: &C,
    and_generator: &mut AndTripleGenerator<P>,
    channel: &mut Channel,
    rng: &mut RNG,
) -> swanky_error::Result<(Vec<AuthShare<P>>, Vec<AuthShare<P>>)>
where
    C: CircuitInputMapper<CircuitAnalyzer> + CircuitInputMapper<WirePreProcessor<P>>,
{
    // First count the number of gate types.
    let mut circuit_analyzer = CircuitAnalyzer::new();
    circuit_analyzer.eval(circuit)?;

    let nands = circuit_analyzer.nands();
    let ninputs = circuit_analyzer.ninputs();
    let nconstants = circuit_analyzer.nconstants();

    // If we have too few AND gates, we need to generate at
    // least 320 AND triples in order for the protocol to be secure.
    let nand_triples = if 0 < nands && nands < 320 { 320 } else { nands };

    // Create as many random AND triples as there are AND gates.
    let mut rand_and_triples = Vec::with_capacity(nand_triples);
    // We only generate AND triples if there are any AND gates in the circuit
    // to begin with
    if nands > 0 {
        and_generator.generate(nand_triples, &mut rand_and_triples, channel, rng)?;
    }

    // Create as many authenticated shares as there are AND, Constant and Input gates.
    let mut auth_shares = Vec::with_capacity(nands + ninputs + nconstants);
    and_generator.auth_share_generator_mut().generate(
        nands + ninputs + nconstants,
        &mut auth_shares,
        channel,
        rng,
    )?;
    let wire_preprocessor = WirePreProcessor::new(auth_shares, nands, and_generator.delta());
    let (left_wires, right_wires, auth_shares) = wire_preprocessor.execute(circuit)?;

    // We only correlate the generated AND triples if there are any AND gates in the circuit
    // to begin with.
    let mut known_triples = Vec::with_capacity(nands);
    if nands > 0 {
        and_generator.to_known_triple(
            &rand_and_triples[..nands],
            &left_wires,
            &right_wires,
            &mut known_triples,
            channel,
        )?;
    }

    Ok((auth_shares, known_triples))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PartyEvaluator, PartyGarbler};
    use fancy_circuits::binary::TestBinaryAddition;
    use swanky_rng::SwankyRng;

    #[test]
    fn test_preprocessing() {
        let input_size = 800;
        let circuit = TestBinaryAddition(input_size);
        let (_shares_gb, _shares_ev) = swanky_channel::local::local_channel_pair(
            |c| {
                let mut rng = SwankyRng::new();
                let mut generator_and_triples =
                    AndTripleGenerator::<PartyGarbler>::new(c, &mut rng)?;
                Ok(f_preprocessing(
                    &circuit,
                    &mut generator_and_triples,
                    c,
                    &mut rng,
                ))
            },
            |c| {
                let mut rng = SwankyRng::new();
                let mut generator_and_triples =
                    AndTripleGenerator::<PartyEvaluator>::new(c, &mut rng)?;
                Ok(f_preprocessing(
                    &circuit,
                    &mut generator_and_triples,
                    c,
                    &mut rng,
                ))
            },
        )
        .unwrap();
    }
}
