#[cfg(test)]
mod tests {
    use crate::psi::circuit_psi::{
        base_psi::{receiver::OpprfReceiver, sender::OpprfSender, BasePsi},
        tests::utils::*,
        *,
    };
    use proptest::prelude::*;

    const SET_SIZE: usize = 1 << 8;
    const PAYLOAD_MAX: u128 = 100000;
    const ELEMENT_MAX: u128 = u64::MAX as u128;

    proptest! {
            #[test]
            fn test_psty_cardinality(
                seed_sx in any::<u64>(),
                seed_rx in any::<u64>(),
                set in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX))
            {

                let cardinality = run_psty_u128::<_, _, u128>(
                    &set,
                    None,
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
