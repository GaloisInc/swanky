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
pub mod backend_extfield;
pub mod backend_multifield;
pub mod backend_trait;
pub mod circuit_ir;
mod gadgets;
pub mod plaintext;

#[allow(dead_code)] // because, well, it's not used yet.
mod dora;

mod ram;

pub mod edabits;
pub mod fields;
pub mod homcom;
pub mod mac;
mod memory;
mod sieveir_phase2;
pub mod sieveir_reader_fbs;
pub mod sieveir_reader_text;
pub use backend::DietMacAndCheese;
mod plugins;
pub mod svole_thread;
pub mod svole_trait;

use ocelot::svole::{
    LpnParams, LPN_EXTEND_EXTRASMALL, LPN_EXTEND_MEDIUM, LPN_EXTEND_SMALL, LPN_EXTEND_SMALL_MEDIUM,
    LPN_SETUP_EXTRASMALL, LPN_SETUP_MEDIUM, LPN_SETUP_SMALL, LPN_SETUP_SMALL_MEDIUM,
};
use serde::Deserialize;
use std::fmt::Display;

/// Size of LPN parameters
///
/// This parameter is available to the user to indicate, at a high-level, the size of the LPN parameters
/// without specifiying exactly their values.
/// It has three possible values small, medium and large.
/// The size is mapped to actual LPN parameters using [`mapping_lpn_size`] or
/// [`mapping_lpn_size_large_field`].
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LpnSize {
    Small,
    #[default]
    Medium,
    Large,
}

impl Display for LpnSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LpnSize::Small => write!(f, "small"),
            LpnSize::Medium => write!(f, "medium"),
            LpnSize::Large => write!(f, "large"),
        }
    }
}

/// Mapping [`LpnSize`] to LPN parameters
pub(crate) fn mapping_lpn_size(lpn_size: LpnSize) -> (LpnParams, LpnParams) {
    match lpn_size {
        LpnSize::Small => (LPN_SETUP_SMALL, LPN_EXTEND_SMALL),
        LpnSize::Medium => (LPN_SETUP_SMALL_MEDIUM, LPN_EXTEND_SMALL_MEDIUM),
        LpnSize::Large => (LPN_SETUP_MEDIUM, LPN_EXTEND_MEDIUM),
    }
}

/// Mapping [`LpnSize`] to LPN parameters for large fields
///
/// For large fields it is usually desriable to use smaller LPN parameters.
/// This makes the computing svole extensions faster (even though it draws fewer at a time)
/// and also it reduces the memory usage by reducing the size of the vectors holding the VOLEs.
pub(crate) fn mapping_lpn_size_large_field(lpn_size: LpnSize) -> (LpnParams, LpnParams) {
    match lpn_size {
        LpnSize::Small => (LPN_SETUP_EXTRASMALL, LPN_EXTEND_EXTRASMALL),
        LpnSize::Medium => (LPN_SETUP_SMALL, LPN_EXTEND_SMALL),
        LpnSize::Large => (LPN_SETUP_SMALL_MEDIUM, LPN_EXTEND_SMALL_MEDIUM),
    }
}
