use generic_array::typenum::Unsigned;
use scuttlebutt::field::FiniteField;
use simple_arith_circuit::Circuit;

/// Compute the number of compression rounds. If there are no multiplication gates, we'll have zero rounds.
pub(crate) fn nrounds<F: FiniteField>(circuit: &Circuit<F>, compression_factor: usize) -> usize {
    // XXX replace with `u64::checked_log` once it gets standardized.
    let nrounds = (circuit.nmuls() as f64)
        .log(compression_factor as f64)
        .floor() as usize;
    if nrounds > 0 {
        nrounds - 1
    } else {
        nrounds
    }
}

/// Validates that the number of parties, compression factor, and number of
/// repetitions achieves 128 bits of security for the particular finite field.
pub(crate) fn validate_parameters<F: FiniteField>(
    nparties: usize,
    compression_factor: usize,
    repetitions: usize,
) -> bool {
    // XXX: Currently we only use the parameters from Table 4 in the Limbo paper,
    // which provides valid parameter settings for `F_{2^{64}}` (and larger fields).
    if F::NumberOfBitsInBitDecomposition::USIZE >= 64 {
        match (nparties, compression_factor, repetitions) {
            (16, 8, 40)
            | (16, 16, 38)
            | (32, 8, 34)
            | (32, 16, 32)
            | (64, 8, 30)
            | (64, 16, 28)
            | (128, 8, 27)
            | (128, 16, 25) => true,
            _ => false,
        }
    } else {
        false
    }
}
