//! Authenticated garbling for maliciously secure two-party computation.
//!
//! This implements the authenticated garbling protocol presented by Katz et
//! al.[^1], and in particular, Figure 3 from that paper. The garbler and
//! evaluator are broken up into four distinct phases: (1) offline, (2) online,
//! (3) validation, and (4) output. These roughly correspond to (1) Steps 1-2,
//! (2) Steps 3-6, (3) Steps 7-8, and (4) Step 9 in the aforementioned Figure 3
//! of the paper. The API is designed to enforce that these phases are run in
//! order.
//!
//! # Example
//!
//! Below is an example that shows the garbling and evaluation of AES-128, where
//! the garbler's input is the key, and the evaluator's input is the block.
//!
//! ```
//! # use fancy_traits::{FancyEncode, FancyOutput};
//! # use rand::RngExt;
//! # use swanky_authenticated_garbling::{GarblerOffline, EvaluatorOffline};
//! # fn main() -> swanky_error::Result<()> {
//! let mut rng = swanky_rng::SwankyRng::new();
//! let circuit = fancy_circuits::crypto::aes::Aes128::new();
//! let key: Vec<u16> = (0..128).map(|_| rng.random::<u16>() % 2).collect();
//! let block: Vec<u16> = (0..128).map(|_| rng.random::<u16>() % 2).collect();
//! let (_, outputs) = swanky_channel::local::local_channel_pair(
//!     |channel| {
//!         let mut rng = swanky_rng::SwankyRng::new();
//!         // The offline phase is run first. `GarblerOffline::initialize` sets up
//!         // the authenticated triples for the provided circuit.
//!         let gb = GarblerOffline::initialize(&circuit, channel, &mut rng)?;
//!         // Evaluate the circuit locally to produce necessary offline information.
//!         let (outputs, gb) = gb.execute()?;
//!         // Finalize the offline phase, returning a `GarblerOnline`.
//!         let mut gb = gb.finalize(channel)?;
//!         // Encode inputs as needed.
//!         let mut inputs = gb.encode_many(&key, &vec![2; 128], channel)?;
//!         let their = gb.receive_many(&vec![2; 128], channel)?;
//!         inputs.extend(their);
//!         // There's nothing for the garbler to run in the online phase, so the
//!         //next step is to finalize the phase, returning a `GarblerValidator`.
//!         let gb = gb.finalize(channel)?;
//!         // Validate the computation, returning a `GarblerOutput`.
//!         let mut gb = gb.validate(inputs, channel)?;
//!         // Retrieve outputs as needed.
//!         let outputs = gb.outputs(&outputs, channel)?;
//!         assert!(outputs.is_none());
//!         Ok(())
//!     },
//!     |channel| {
//!         let mut rng = swanky_rng::SwankyRng::new();
//!         // The offline phase is run first. `EvaluatorOffline::initialize` sets up
//!         // the authenticated triples for the provided circuit.
//!         let ev = EvaluatorOffline::initialize(&circuit, channel, &mut rng)?;
//!         // There's nothing for the evaluator to run in the offline phase, so
//!         // the next step is to finalize the phase, returning an `EvaluatorOnline`.
//!         let mut ev = ev.finalize(channel)?;
//!         // Encode inputs as needed.
//!         let mut inputs = ev.receive_many(&vec![2; 128], channel)?;
//!         let mine = ev.encode_many(&block, &vec![2; 128], channel)?;
//!         inputs.extend(mine);
//!         // Evaluate the circuit locally using the offline information.
//!         let (outputs, ev) = ev.execute(inputs)?;
//!         // Finalize the online phase, returning an `EvaluatorValidator`.
//!         let ev = ev.finalize(channel)?;
//!         // Validate the computation, returning an `EvaluatorOutput`.
//!         let mut ev = ev.validate(channel)?;
//!         // Retrieve outputs as needed.
//!         let outputs = ev.outputs(&outputs, channel)?;
//!         Ok(outputs.expect("evaluator outputs should not be `None`"))
//!     },
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! References:
//! [^1]: J. Katz, S. Ranellucci, M. Rosulek, X. Wang. "Optimizing Authenticated
//! Garbling for Faster Secure Two-Party Computation".
//! <https://eprint.iacr.org/2018/578.pdf>
#![deny(missing_docs)]

mod evaluator;
pub use evaluator::{EvaluatorOffline, EvaluatorOnline, EvaluatorOutput, EvaluatorValidator};
mod garbler;
pub use garbler::{GarblerOffline, GarblerOnline, GarblerOutput, GarblerValidator};
mod preprocesser;
pub use preprocesser::WirePreProcessor;
mod wire;
pub use wire::EvaluatorWire;
mod vec_wrapper;

swanky_party::party_system! {
    mod ps {
        /// The garbler party.
        PartyGarbler,
        /// The evaluator party.
        PartyEvaluator,
    }
}

pub use ps::{PartyEvaluator, PartyGarbler};

#[cfg(test)]
mod tests;
