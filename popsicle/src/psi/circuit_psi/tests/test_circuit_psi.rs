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

    pub fn cardinality(set_a: Vec<Vec<u8>>, set_b: Vec<Vec<u8>>) -> usize {
        let set_a: HashSet<Block> = HashSet::from_iter(u8_vec_block(&set_a, ELEMENT_SIZE));
        let set_b: HashSet<Block> = HashSet::from_iter(u8_vec_block(&set_b, ELEMENT_SIZE));

        set_a.intersection(&set_b).count()
    }

    proptest! {
            #[test]
            fn test_psty_cardinality(
                seed_sx in any::<u128>(),
                seed_rx in any::<u128>(),
                set in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX))
            {

                let cardinality = run_psty_u128::<_, _>(
                    &set,
                    None,
                    seed_sx,
                    seed_rx,
                    &mut fancy_cardinality::<Ev, _>(),
                    &mut fancy_cardinality::<Gb, _>(),
                )
                .unwrap();
                assert!(
                    cardinality == (SET_SIZE as u128),
                    "The PSI Cardinality is wrong! The result was {} and should be {}",
                    cardinality,
                    SET_SIZE
                );
        }
    }
}
