//! Testing Circuit Psi on various circuits
#[cfg(test)]
mod tests {
    use crate::psi::circuit_psi::{
        tests::{
            utils::{circuit_runner::*, type_aliases::*, *},
            *,
        },
        *,
    };
    use scuttlebutt::AesRng;
    use std::collections::HashSet;

    // Computes the cardinality of the intersection in the clear
    pub fn cardinality_in_clear(set_a: &[Vec<u8>], set_b: &[Vec<u8>]) -> usize {
        let set_a: HashSet<Block> = HashSet::from_iter(u8_vec_block(&set_a, ELEMENT_SIZE));
        let set_b: HashSet<Block> = HashSet::from_iter(u8_vec_block(&set_b, ELEMENT_SIZE));

        set_a.intersection(&set_b).count()
    }
    // Computes the payload sum:
    //
    // If an intersection happens, then the associated payloads are summed,
    // otherwise they are discarded
    pub fn payload_sum(
        set_a: &[Vec<u8>], // Assume sets are ordered for simplicity of test
        set_b: &[Vec<u8>],
        payload_a: &[u128],
        payload_b: &[u128],
    ) -> u128 {
        let set_a: Vec<Block> = u8_vec_block(&set_a, ELEMENT_SIZE);
        let set_b: Vec<Block> = u8_vec_block(&set_b, ELEMENT_SIZE);

        let mut acc = 0;
        for i in 0..set_a.len() {
            if set_a == set_b {
                acc += payload_a[i] + payload_b[i];
            }
        }
        acc
    }

    #[test]
    // Test the fancy cardinality of the intersection circuit
    // on sets the same sets
    fn test_psty_circuit_cardinality_same_sets() {
        let mut rng = AesRng::new();
        let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
        let cardinality = run_psty_no_payloads_u128::<_, _>(
            &set,
            &set,
            rng.gen(),
            rng.gen(),
            &mut fancy_cardinality::<Ev, _>(),
            &mut fancy_cardinality::<Gb, _>(),
        )
        .unwrap() as usize;
        assert!(
            cardinality == SET_SIZE,
            "The PSI Cardinality on the same set is wrong! The result was {} and should be {}",
            cardinality,
            SET_SIZE
        );
    }
    #[test]
    // Test the fancy cardinality of the intersection circuit
    // on sets that are one item off
    fn test_psty_circuit_cardinality_one_off_sets() {
        let mut rng = AesRng::new();

        let set_a = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
        let set_b = enum_ids(SET_SIZE, 1, ELEMENT_SIZE);

        let cardinality = run_psty_no_payloads_u128::<_, _>(
            &set_a,
            &set_b,
            rng.gen(),
            rng.gen(),
            &mut fancy_cardinality::<Ev, _>(),
            &mut fancy_cardinality::<Gb, _>(),
        )
        .unwrap() as usize;
        assert!(
            cardinality == (SET_SIZE - 1),
            "The PSI Cardinality on sets with one different item is wrong! The result was {} and should be {}",
            cardinality,
            SET_SIZE - 1
        );
    }
    #[test]
    // Test the fancy cardinality of the intersection circuit
    // on disjoints sets
    fn test_psty_circuit_cardinality_disjoint_sets() {
        let mut rng = AesRng::new();

        let set_a = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
        let set_b = enum_ids(SET_SIZE, SET_SIZE as u64, ELEMENT_SIZE);

        let cardinality = run_psty_no_payloads_u128::<_, _>(
            &set_a,
            &set_b,
            rng.gen(),
            rng.gen(),
            &mut fancy_cardinality::<Ev, _>(),
            &mut fancy_cardinality::<Gb, _>(),
        )
        .unwrap() as usize;
        assert!(
            cardinality == (SET_SIZE - 1),
            "The PSI Cardinality on disjoint sets is wrong! The result was {} and should be {}",
            cardinality,
            0
        );
    }
    #[test]
    // Test the fancy cardinality of the intersection circuit
    // on random sets
    fn test_psty_circuit_cardinality_random_sets() {
        let mut rng = AesRng::new();

        let set_a = rand_u8_vec(SET_SIZE, 2u128.pow(ELEMENT_SIZE as u32 * 8), &mut rng);
        let set_b = rand_u8_vec(SET_SIZE, 2u128.pow(ELEMENT_SIZE as u32 * 8), &mut rng);

        let cardinality = run_psty_no_payloads_u128::<_, _>(
            &set_a,
            &set_b,
            rng.gen(),
            rng.gen(),
            &mut fancy_cardinality::<Ev, _>(),
            &mut fancy_cardinality::<Gb, _>(),
        )
        .unwrap() as usize;

        let cardinality_in_clear = cardinality_in_clear(&set_a, &set_b);
        assert!(
            cardinality == cardinality_in_clear,
            "The PSI Cardinality on random sets is wrong! The result was {} and should be {}",
            cardinality,
            cardinality_in_clear
        );
    }
    #[test]
    // Test the fancy payload sum circuit, where if an intersection happens
    // then the associated payloads are aggregated.
    // This first test checks that the circuit works when we intersect a set with itself
    // and sum random payloads together.
    // The payload sum should be the summation of all payloads in this case
    fn test_psty_circuit_payload_sum_same_set_rand_payloads() {
        let mut rng = AesRng::new();
        let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
        let payloads_a = rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng);
        let payloads_b = rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng);

        let sum_in_clear = payload_sum(&set, &set, &payloads_a, &payloads_b);
        let sum = run_psty_u128::<_, _>(
            &set,
            &set,
            &int_vec_block512(payloads_a, PAYLOAD_SIZE),
            &int_vec_block512(payloads_b, PAYLOAD_SIZE),
            rng.gen(),
            rng.gen(),
            &mut fancy_payload_sum::<Ev, _>(),
            &mut fancy_payload_sum::<Gb, _>(),
        )
        .unwrap();

        assert!(
            sum == sum_in_clear,
            "The PSI Payload Sum on the same set is wrong! The result was {} and should be {}",
            sum,
            sum_in_clear
        );
    }

    #[test]
    // Test the fancy payload sum circuit, where if an intersection happens
    // then the associated payloads are aggregated.
    // This test checks that the circuit works when we intersect disjoint sets
    // the payload sum should be 0.
    fn test_psty_circuit_payload_sum_disjoint_sets_rand_payloads() {
        let mut rng = AesRng::new();
        let set_a = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
        let set_b = enum_ids(SET_SIZE, SET_SIZE as u64, ELEMENT_SIZE);
        let payloads_a = rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng);
        let payloads_b = rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng);

        let sum_in_clear = payload_sum(&set_a, &set_b, &payloads_a, &payloads_b);
        let sum = run_psty_u128::<_, _>(
            &set_a,
            &set_b,
            &int_vec_block512(payloads_a, PAYLOAD_SIZE),
            &int_vec_block512(payloads_b, PAYLOAD_SIZE),
            rng.gen(),
            rng.gen(),
            &mut fancy_payload_sum::<Ev, _>(),
            &mut fancy_payload_sum::<Gb, _>(),
        )
        .unwrap();

        assert!(
            sum == sum_in_clear,
            "The PSI Payload Sum for disjoint sets is wrong! The result was {} and should be {}",
            sum,
            sum_in_clear
        );
    }
}
