/*!
A 'diet' implementation of the Mac'n'Cheese interactive ZKP protocol.

Diet Mac'n'Cheese (DMC) can be used a both an application and a library. See the
`README` (and CLI help text) for information regarding the configuration and
running of the prover and verifier applications.

At a high level, DMC provides the following:

- In-memory representations of SIEVE IR (the circuit format) resources
- A frontend to parse SIEVE IR from flatbuffers
- A frontend to parse SIEVE IR from text
- Party-generic and multithreaded implementations of sVOLE
- A party-generic circuit evaluation interface

There is an example of using DMC as a library in the crate's `examples`
directory; this shows off everything but the SIEVE IR parsers. Additional detail
can be found in the module documentation for each component.
 */

mod backend_multifield;
pub use backend_multifield::EvaluatorCirc;
pub mod circuit_ir;
pub mod sieveir_reader_fbs;
pub mod sieveir_reader_text;
pub mod svole_thread;
pub mod svole_trait;

mod backend;
pub(crate) use backend::DietMacAndCheese;
mod backend_extfield;
mod backend_trait;
mod dora;
mod edabits;
mod fields;
mod gadgets;
mod homcom;
mod mac;
mod memory;
mod plaintext;
mod plugins;
mod ram;
mod sieveir_phase2;

use ocelot::svole::{
    LpnParams, LPN_EXTEND_EXTRASMALL, LPN_EXTEND_MEDIUM, LPN_EXTEND_SMALL, LPN_EXTEND_SMALL_MEDIUM,
    LPN_SETUP_EXTRASMALL, LPN_SETUP_MEDIUM, LPN_SETUP_SMALL, LPN_SETUP_SMALL_MEDIUM,
};
use serde::Deserialize;
use std::fmt::Display;

/// The size of LPN parameters to use for sVOLE.
///
/// At a high-level, these parameters describe the number of values to generate
/// during the setup and extend phases of the sVOLE protocol.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LpnSize {
    /// Small LPN parameter set
    Small,
    /// Medium LPN parameter set
    #[default]
    Medium,
    /// Large LPN parameter set
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

/// Mapping [`LpnSize`] to LPN parameters.
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
/// This makes computing svole extensions faster (even though it draws fewer at a time)
/// and also it reduces the memory usage by reducing the size of the vectors holding the VOLEs.
pub(crate) fn mapping_lpn_size_large_field(lpn_size: LpnSize) -> (LpnParams, LpnParams) {
    match lpn_size {
        LpnSize::Small => (LPN_SETUP_EXTRASMALL, LPN_EXTEND_EXTRASMALL),
        LpnSize::Medium => (LPN_SETUP_SMALL, LPN_EXTEND_SMALL),
        LpnSize::Large => (LPN_SETUP_SMALL_MEDIUM, LPN_EXTEND_SMALL_MEDIUM),
    }
}

use mac_n_cheese_sieve_parser::Number;

/// Convert a [`Number`] into `Some(u64)` if it'll fit, `None` otherwise.
pub(crate) fn number_to_u64(x: &Number) -> eyre::Result<u64> {
    use crypto_bigint::SplitMixed;
    let (hi, lo): (_, crypto_bigint::U64) = x.split_mixed();
    if hi == crypto_bigint::Uint::ZERO {
        Ok(u64::from(lo))
    } else {
        eyre::bail!("Number does not fit in u64")
    }
}

#[cfg(test)]
proptest::proptest! {
    #[test]
    fn test_successful_conversion(x in 0..=u64::MAX) {
        proptest::prop_assert!(
            number_to_u64(&Number::from_u64(x)).is_ok() && number_to_u64(&Number::from_u64(x)).unwrap() == x
        );
    }
}

#[cfg(test)]
proptest::proptest! {
    #[test]
    fn test_unsuccessful_conversion(x in u128::from(u64::MAX)..=u128::MAX) {
        proptest::prop_assert!(number_to_u64(&Number::from_u128(x)).is_err());
    }
}
