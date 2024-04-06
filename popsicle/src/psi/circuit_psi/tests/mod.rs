//! Testing Suite for Circuit Psi
pub mod test_base_psi;
pub mod test_circuit_psi;
pub mod test_hashing;
pub mod test_init;
pub mod test_opprf;
pub mod utils;

#[cfg(test)]
const SET_SIZE: usize = 1 << 8;
#[cfg(test)]
const PAYLOAD_MAX: u128 = 10000;
#[cfg(test)]
const ELEMENT_MAX: u128 = 10000;
#[cfg(test)]
const DEFAULT_SEED: u64 = 0;
#[cfg(test)]
const TEST_TRIALS: usize = 10;
