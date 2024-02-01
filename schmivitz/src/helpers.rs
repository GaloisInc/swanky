//! Helper methods that are used for computation in both proving and verifying.
//!
//!

use swanky_field_binary::F128b;

/// Convert a list of field elements into a single 128-bit value.
///
/// TODO: This is not correct!!!
#[allow(unused)]
pub(crate) fn combine(values: [F128b; 128]) -> F128b {
    values.into_iter().sum()
}
