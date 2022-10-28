/*!

`diet_mac_and_cheese` provides a diet/light implementation of the Mac'n'Cheese protocol.

The library provides structures to operate a prover `DietMacAndCheeseProver` or a verifier `DietMacAndCheeseVerifier`
with an interface to initialize and execute the protocol at a gate-by-gate level.
Gates operates on input values that can be either public or private.
When a gate takes on public values it produces a public value, and when a gate is provided private values
then it produces a private value.
Public and private values are ingested using the pair of functions `input_public()`/`input_private()`
and they return public/private values whose type is exposed to to the user as `ValueProver` and `ValueVerifier`.

Note that the interfaces for the prover and the verifier are almost identical at a high-level, except
for the `input_private()` function.
*/

mod backend;
mod error;

pub use backend::{
    from_bytes_le, DietMacAndCheeseProver, DietMacAndCheeseVerifier, ValueProver, ValueVerifier,
};
pub use error::{Error, Result};

#[cfg(feature = "exe")]
mod backend_zki;
#[cfg(feature = "exe")]
pub mod cli;
