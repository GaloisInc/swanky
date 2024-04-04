//! Testing Circuit Psi on various circuits
#[cfg(test)]
mod tests {
    use crate::psi::circuit_psi::{
        tests::utils::{circuit_runner::*, type_aliases::*, *},
        *,
    };
    use proptest::prelude::*;
    use std::collections::HashSet;

    const SET_SIZE: usize = 1 << 8;
    const PAYLOAD_MAX: u128 = 100000;
    const ELEMENT_MAX: u128 = u64::MAX as u128;

    // Computes the cardinality of the intersection in the clear
    pub fn cardinality_in_clear(set_a: Vec<Vec<u8>>, set_b: Vec<Vec<u8>>) -> usize {
        let set_a: HashSet<Block> = HashSet::from_iter(u8_vec_block(&set_a, ELEMENT_SIZE));
        let set_b: HashSet<Block> = HashSet::from_iter(u8_vec_block(&set_b, ELEMENT_SIZE));

        set_a.intersection(&set_b).count()
    }

    proptest! {
            #[test]
            // Test the fancy cardinality of the intersection circuit
            fn test_psty_cardinality(
                seed_sx in any::<u128>(),
                seed_rx in any::<u128>(),
                set_a in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX),
                set_b in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX),
            )
            {

                let cardinality = run_psty_u128::<_, _>(
                    &set_a,
                    &set_b,
                    None,
                    None,
                    seed_sx,
                    seed_rx,
                    &mut fancy_cardinality::<Ev, _>(),
                    &mut fancy_cardinality::<Gb, _>(),
                )
                .unwrap() as usize;
            let cardinality_in_clear = cardinality_in_clear(set_a, set_b);
                assert!(
                    cardinality == cardinality_in_clear,
                    "The PSI Cardinality is wrong! The result was {} and should be {}",
                    cardinality,
                    SET_SIZE
                );
        }
    }
}
