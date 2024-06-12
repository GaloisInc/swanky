//! Testing Circuit Psi on various circuits
#[cfg(test)]
mod tests {
    use crate::psi::circuit_psi::{
        evaluator::OpprfPsiEvaluator,
        garbler::OpprfPsiGarbler,
        tests::{utils::*, *},
        utils,
        utils::*,
        *,
    };
    use scuttlebutt::{AesRng, Block};
    use std::{collections::HashSet, os::unix::net::UnixStream, thread};

    // Computes the cardinality of the intersection in the clear
    pub fn cardinality_in_clear(set_a: &[Vec<u8>], set_b: &[Vec<u8>]) -> usize {
        let set_a: HashSet<Block> = HashSet::from_iter(u8_vec_block(&set_a, PRIMARY_KEY_SIZE));
        let set_b: HashSet<Block> = HashSet::from_iter(u8_vec_block(&set_b, PRIMARY_KEY_SIZE));

        set_a.intersection(&set_b).count()
    }
    // Computes the payload sum:
    //
    // If an intersection happens, then the associated payloads are summed,
    // otherwise they are discarded
    pub fn payload_sum(
        primary_keys_a: &[Vec<u8>], // Assume primary_keys are ordered for simplicity of test
        primary_keys_b: &[Vec<u8>],
        payload_a: &[u128],
        payload_b: &[u128],
    ) -> u128 {
        let primary_keys_a: Vec<Block> = u8_vec_block(&primary_keys_a, PRIMARY_KEY_SIZE);
        let primary_keys_b: Vec<Block> = u8_vec_block(&primary_keys_b, PRIMARY_KEY_SIZE);

        let mut acc = 0;
        for i in 0..primary_keys_a.len() {
            if primary_keys_a == primary_keys_b {
                acc += payload_a[i] + payload_b[i];
            }
        }
        acc
    }

    #[cfg(test)]
    pub fn psty_cardinality(
        set_a: &[Vec<u8>],
        set_b: &[Vec<u8>],
        seed_sx: u128,
        seed_rx: u128,
    ) -> Result<u128, Error> {
        let (sender, receiver) = UnixStream::pair().unwrap();
        thread::scope(|s| {
            let _ = s.spawn(|| {
                let mut channel = setup_channel(sender);
                let mut gb_psi: _ =
                    OpprfPsiGarbler::<_, AesRng>::new(&mut channel, Block::from(seed_sx)).unwrap();

                let intersection_results = gb_psi.intersect(set_a).unwrap();
                let res = fancy_cardinality(
                    &mut gb_psi.gb,
                    &intersection_results.intersection.existence_bit_vector,
                )
                .unwrap();
                gb_psi.gb.outputs(res.wires()).unwrap();
            });
            let mut channel = setup_channel(receiver);

            let mut ev_psi =
                OpprfPsiEvaluator::<_, AesRng>::new(&mut channel, Block::from(seed_rx)).unwrap();
            let intersection_results = ev_psi.intersect(set_b).unwrap();
            let res = fancy_cardinality(
                &mut ev_psi.ev,
                &intersection_results.intersection.existence_bit_vector,
            )?;
            let res_out = ev_psi
                .ev
                .outputs(&res.wires().to_vec())
                .unwrap()
                .expect("evaluator should produce outputs");
            Ok(utils::binary_to_u128(res_out))
        })
    }
    #[cfg(test)]
    pub fn psty_payload_sum(
        primary_keys_a: &[Vec<u8>],
        primary_keys_b: &[Vec<u8>],
        payload_a: &[Block512],
        payload_b: &[Block512],
        seed_sx: u128,
        seed_rx: u128,
    ) -> Result<u128, Error> {
        let (sender, receiver) = UnixStream::pair().unwrap();
        thread::scope(|s| {
            let _ = s.spawn(|| {
                let mut channel = setup_channel(sender);
                let mut gb_psi: _ =
                    OpprfPsiGarbler::<_, AesRng>::new(&mut channel, Block::from(seed_sx)).unwrap();

                let intersection_results = gb_psi
                    .intersect_with_payloads(primary_keys_a, Some(payload_a))
                    .unwrap();
                let res = fancy_payload_sum(
                    &mut gb_psi.gb,
                    &intersection_results.intersection.existence_bit_vector,
                    &intersection_results.payloads.sender_payloads,
                    &intersection_results.payloads.receiver_payloads,
                )
                .unwrap();
                gb_psi.gb.outputs(res.wires()).unwrap();
            });
            let mut channel = setup_channel(receiver);

            let mut ev_psi =
                OpprfPsiEvaluator::<_, AesRng>::new(&mut channel, Block::from(seed_rx)).unwrap();
            let intersection_results = ev_psi
                .intersect_with_payloads(primary_keys_b, Some(payload_b))
                .unwrap();
            let res = fancy_payload_sum(
                &mut ev_psi.ev,
                &intersection_results.intersection.existence_bit_vector,
                &intersection_results.payloads.sender_payloads,
                &intersection_results.payloads.receiver_payloads,
            )
            .unwrap();
            let res_out = ev_psi
                .ev
                .outputs(&res.wires().to_vec())
                .unwrap()
                .expect("evaluator should produce outputs");
            Ok(utils::binary_to_u128(res_out))
        })
    }
    #[test]
    // Test the fancy cardinality of the intersection circuit
    // on the same set
    fn test_psty_circuit_cardinality_same_sets() {
        let mut rng = AesRng::new();
        let set = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
        let cardinality = psty_cardinality(&set, &set, rng.gen(), rng.gen()).unwrap() as usize;
        assert!(
            cardinality == SET_SIZE,
            "The PSI Cardinality on the same primary_keysis wrong! The result was {} and should be {}",
            cardinality,
            SET_SIZE
        );
    }
    #[test]
    // Test the fancy cardinality of the intersection circuit
    // on sets that are one item off
    fn test_psty_circuit_cardinality_one_off_sets() {
        let mut rng = AesRng::new();

        let set_a = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
        let set_b = enum_ids(SET_SIZE, 1, PRIMARY_KEY_SIZE);

        let cardinality = psty_cardinality(&set_a, &set_b, rng.gen(), rng.gen()).unwrap() as usize;
        assert!(
            cardinality == (SET_SIZE - 1),
            "The PSI Cardinality on primary_keys with one different item is wrong! The result was {} and should be {}",
            cardinality,
            SET_SIZE - 1
        );
    }
    #[test]
    // Test the fancy cardinality of the intersection circuit
    // on disjoints sets
    fn test_psty_circuit_cardinality_disjoint_sets() {
        let mut rng = AesRng::new();

        let set_a = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
        let set_b = enum_ids(SET_SIZE, SET_SIZE as u64, PRIMARY_KEY_SIZE);

        let cardinality = psty_cardinality(&set_a, &set_b, rng.gen(), rng.gen()).unwrap() as usize;
        assert!(
            cardinality == 0,
            "The PSI Cardinality on disjoint primary_keys is wrong! The result was {} and should be {}",
            cardinality,
            0
        );
    }
    #[test]
    // Test the fancy cardinality of the intersection circuit
    // on random sets
    fn test_psty_circuit_cardinality_random_sets() {
        let mut rng = AesRng::new();

        let set_a = rand_u8_vec(SET_SIZE, 2u128.pow(PRIMARY_KEY_SIZE as u32 * 8), &mut rng);
        let set_b = rand_u8_vec(SET_SIZE, 2u128.pow(PRIMARY_KEY_SIZE as u32 * 8), &mut rng);

        let cardinality = psty_cardinality(&set_a, &set_b, rng.gen(), rng.gen()).unwrap() as usize;

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
    // This first test checks that the circuit works when we intersect a set of primary_keys with itself
    // and sum random payloads together.
    // The payload sum should be the summation of all payloads in this case
    fn test_psty_circuit_payload_sum_same_keys_rand_payloads() {
        let mut rng = AesRng::new();
        let primary_keys = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
        let payloads_a = rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng);
        let payloads_b = rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng);

        let sum_in_clear = payload_sum(&primary_keys, &primary_keys, &payloads_a, &payloads_b);
        let sum = psty_payload_sum(
            &primary_keys,
            &primary_keys,
            &int_vec_block512(payloads_a, PAYLOAD_SIZE),
            &int_vec_block512(payloads_b, PAYLOAD_SIZE),
            rng.gen(),
            rng.gen(),
        )
        .unwrap();

        assert!(
            sum == sum_in_clear,
            "The PSI Payload Sum on the same primary_keysis wrong! The result was {} and should be {}",
            sum,
            sum_in_clear
        );
    }

    #[test]
    // Test the fancy payload sum circuit, where if an intersection happens
    // then the associated payloads are aggregated.
    // This test checks that the circuit works when we intersect disjoint sets of primary_keys
    // the payload sum should be 0.
    fn test_psty_circuit_payload_sum_disjoint_primary_keys_rand_payloads() {
        let mut rng = AesRng::new();
        let primary_keys_a = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
        let primary_keys_b = enum_ids(SET_SIZE, SET_SIZE as u64, PRIMARY_KEY_SIZE);
        let payloads_a = rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng);
        let payloads_b = rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng);

        let sum_in_clear = payload_sum(&primary_keys_a, &primary_keys_b, &payloads_a, &payloads_b);
        let sum = psty_payload_sum(
            &primary_keys_a,
            &primary_keys_b,
            &int_vec_block512(payloads_a, PAYLOAD_SIZE),
            &int_vec_block512(payloads_b, PAYLOAD_SIZE),
            rng.gen(),
            rng.gen(),
        )
        .unwrap();

        assert!(
            sum == sum_in_clear,
            "The PSI Payload Sum for disjoint primary_keys is wrong! The result was {} and should be {}",
            sum,
            sum_in_clear
        );
    }
}
