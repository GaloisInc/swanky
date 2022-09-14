use scuttlebutt::field::FiniteField;
use simple_arith_circuit::Circuit;

/// Compute the number of compression rounds. If there are no multiplication gates, we'll have zero rounds.
pub fn nrounds<F: FiniteField>(circuit: &Circuit<F>, compression_factor: usize) -> usize {
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
