/*!

`diet_mac_and_cheese` provides a diet/light implementation of the Mac'n'Cheese protocol.

The library provides structures to operate a prover `DietMacAndCheeseProver` or a verifier `DietMacAndCheeseVerifier`
with an interface to initialize and execute the protocol at a gate-by-gate level.
Gates operates on input values that can be either public or private.
When a gate takes on public values it produces a public value, and when a gate is provided private values
then it produces a private value.
Public and private values are ingested using the pair of functions `input_public()`/`input_private()`
and they return public/private values whose type is exposed to to the user as `ValueProver` and `ValueVerifier`.

The `DietMacAndCheeseProver`/`DietMacAndCheeseVerfier` are almost identical at a high-level and differ
solely on the `input_private()` function. Also the API satisfies the following invariant:
if any function call returns an error then any subsequent gate function call
will directly return an error.
*/
mod backend;
pub mod backend_multifield;
pub mod backend_trait;
pub mod circuit_ir;
pub mod edabits;
pub mod fields;
pub mod homcom;
mod memory;
#[allow(clippy::all)]
pub mod read_sieveir_phase2;
mod sieveir_phase2;
pub mod text_reader;
pub use backend::{from_bytes_le, DietMacAndCheeseProver, DietMacAndCheeseVerifier};
mod plugins;
