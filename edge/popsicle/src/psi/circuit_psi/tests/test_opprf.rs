//! Testing the opprf phase in Base Psi
#[cfg(test)]
mod tests {
    use rand::{RngExt, SeedableRng};

    use crate::psi::circuit_psi::{
        base_psi::{BasePsi, receiver::OpprfReceiver, sender::OpprfSender},
        tests::{utils::*, *},
        utils::*,
        *,
    };

    use std::collections::HashSet;
    use swanky_block::Block512;
    use swanky_rng::SwankyRng;

    // Run the base psi up to the opprf exchange
    fn psty_up_to_opprf(
        set: &[Vec<u8>],
        payloads: &[Block512],
        seed_sx: u64,
        seed_rx: u64,
    ) -> (
        OpprfSender,
        OpprfReceiver,
        swanky_error::Result<()>,
        swanky_error::Result<()>,
    ) {
        let ((sender, result_opprf_sender), (receiver, result_opprf_receiver)) =
            swanky_channel::local::local_channel_pair(
                |channel| {
                    let mut rng = SwankyRng::seed_from_u64(seed_sx);
                    let mut sender = OpprfSender::init(true, channel, &mut rng).unwrap();
                    let _ = sender.hash_data(set, Some(payloads), channel, &mut rng);
                    let result_opprf_sender = sender.opprf_exchange(channel, &mut rng);

                    Ok((sender, result_opprf_sender))
                },
                |channel| {
                    let mut rng = SwankyRng::seed_from_u64(seed_rx);
                    let mut receiver = OpprfReceiver::init(true, channel, &mut rng).unwrap();
                    let _ = receiver.hash_data(set, Some(payloads), channel, &mut rng);
                    let result_opprf_receiver = receiver.opprf_exchange(channel, &mut rng);
                    Ok((receiver, result_opprf_receiver))
                },
            )
            .unwrap();

        (sender, receiver, result_opprf_sender, result_opprf_receiver)
    }
    // Check that the opprf preserves the original set by intersecting the party's opprf outputs
    // with the original set. The idea is that if the intersection cardinality in both cases is
    // equal to the original set cardinality, then the hash outputs includes that set
    fn psty_check_opprf_set(sender: OpprfSender, receiver: OpprfReceiver) -> usize {
        let sender_table: HashSet<Block512> =
            HashSet::from_iter(sender.state.opprf_primary_keys_out);
        let receiver_table: HashSet<Block512> =
            HashSet::from_iter(receiver.state.opprf_primary_keys_out);

        receiver_table.intersection(&sender_table).count()
    }
    // Check that the opprf preserves the original payloads by intersecting the party's opprf outputs
    // with the original payload vector. The idea is that if the intersection cardinality in both cases is
    // equal to the original payloads vector cardinality, then the opprf outputs includes that payloads
    fn psty_check_opprf_payload(
        sender: OpprfSender,
        receiver: OpprfReceiver,
        payloads: Vec<Block512>,
    ) -> (usize, usize, usize) {
        let payloads_hash: HashSet<Block512> = HashSet::from_iter(payloads);

        let receiver = receiver.state;
        let receiver_payloads: HashSet<Block512> = HashSet::from_iter(receiver.opprf_payloads_in);
        let receiver_masks: Vec<Block512> = receiver.opprf_payloads_out;
        let sender_masked_payloads: Vec<Block512> = sender.state.opprf_payloads_out;

        // Payloads get masked by the sender to keep them hidden.
        // We need to unmask them to check that everything is fine.
        let mut sender_payloads: HashSet<Block512> = HashSet::new();
        for i in 0..receiver_masks.len() {
            sender_payloads.insert(sender_masked_payloads[i] ^ receiver_masks[i]);
        }

        let intersection_sender = sender_payloads.intersection(&payloads_hash).count();
        let intersection_receiver = receiver_payloads.intersection(&payloads_hash).count();
        (
            intersection_sender,
            intersection_receiver,
            payloads_hash.len(),
        )
    }

    #[test]
    fn test_psty_opprf_sender_succeeded_arbitrary_set() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let set = rand_u8_vec_unique(SET_SIZE, ELEMENT_MAX, &mut rng);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (_, _, result_opprf_sender, _) =
                psty_up_to_opprf(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            assert!(
                result_opprf_sender.is_ok(),
                "PSTY OPPRF failed on the sender side for arbitrary sets"
            );
        }
    }
    #[test]
    fn test_psty_opprf_sender_succeeded_arbitrary_payload() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let set = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
            let payloads =
                int_vec_block512(rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng), PAYLOAD_SIZE);
            let (_, _, result_opprf_sender, _) =
                psty_up_to_opprf(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            assert!(
                result_opprf_sender.is_ok(),
                "PSTY OPPRF failed on the sender side for arbitrary payloads"
            );
        }
    }
    #[test]
    fn test_psty_opprf_sender_succeeded_arbitrary_seed() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let set = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
            let payloads =
                int_vec_block512(rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng), PAYLOAD_SIZE);
            let (_, _, result_opprf_sender, _) =
                psty_up_to_opprf(&set, &payloads, rng.random(), DEFAULT_SEED);
            assert!(
                result_opprf_sender.is_ok(),
                "PSTY OPPRF failed on the sender side for arbitrary sender seeds"
            );
        }
    }
    #[test]
    fn test_psty_opprf_receiver_succeeded_arbitrary_set() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let set = rand_u8_vec_unique(SET_SIZE, ELEMENT_MAX, &mut rng);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (_, _, _, result_opprf_receiver) =
                psty_up_to_opprf(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            assert!(
                result_opprf_receiver.is_ok(),
                "PSTY OPPRF failed on the receiver side for arbitrary set"
            );
        }
    }
    #[test]
    fn test_psty_opprf_receiver_succeeded_arbitrary_payloads() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let set = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
            let payloads =
                int_vec_block512(rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng), PAYLOAD_SIZE);
            let (_, _, _, result_opprf_receiver) =
                psty_up_to_opprf(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            assert!(
                result_opprf_receiver.is_ok(),
                "PSTY OPPRF failed on the receiver side for arbitrary set"
            );
        }
    }
    #[test]
    fn test_psty_opprf_receiver_succeeded_arbitrary_seed() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let set = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (_, _, _, result_opprf_receiver) =
                psty_up_to_opprf(&set, &payloads, DEFAULT_SEED, rng.random());
            assert!(
                result_opprf_receiver.is_ok(),
                "PSTY OPPRF failed on the receiver side for arbitrary set"
            );
        }
    }
    #[test]
    fn test_psty_opprf_preserved_arbitrary_set() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let set = rand_u8_vec_unique(SET_SIZE, ELEMENT_MAX, &mut rng);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (sender, receiver, _, _) =
                psty_up_to_opprf(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            let intersection = psty_check_opprf_set(sender, receiver);

            assert!(
                intersection == SET_SIZE,
                "PSTY OpprfSender did not preserve the original set, the intersection of the tables is {} and should be {}",
                intersection,
                SET_SIZE
            );
        }
    }
    #[test]
    fn test_psty_opprf_preserved_arbitrary_seed() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let set = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (sender, receiver, _, _) =
                psty_up_to_opprf(&set, &payloads, rng.random(), DEFAULT_SEED);
            let intersection = psty_check_opprf_set(sender, receiver);

            assert!(
                intersection == SET_SIZE,
                "PSTY OpprfSender did not preserve the original set, the intersection of the tables is {} and should be {}",
                intersection,
                SET_SIZE
            );
        }
    }
    #[test]
    fn test_psty_opprf_preserved_arbitrary_payloads() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let set = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
            let payloads =
                int_vec_block512(rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng), PAYLOAD_SIZE);
            let (sender, receiver, _, _) =
                psty_up_to_opprf(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            let intersection = psty_check_opprf_set(sender, receiver);

            assert!(
                intersection == SET_SIZE,
                "PSTY OpprfSender did not preserve the original set, the intersection of the tables is {} and should be {}",
                intersection,
                SET_SIZE
            );
        }
    }
    #[test]
    fn test_psty_opprf_preserved_payloads_preserved_arbitrary_set() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let set = rand_u8_vec_unique(SET_SIZE, ELEMENT_MAX, &mut rng);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (sender, receiver, _, _) =
                psty_up_to_opprf(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            let (intersection_sender, _, payloads_len) =
                psty_check_opprf_payload(sender, receiver, payloads);
            assert!(
                intersection_sender == payloads_len,
                "PSTY: Error in sender's payloads hashing table : Expected to find {} payloads, found {}",
                payloads_len,
                intersection_sender
            );
        }
    }
    #[test]
    fn test_psty_opprf_sender_payloads_preserved_arbitrary_payloads() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let set = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
            let payloads =
                int_vec_block512(rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng), PAYLOAD_SIZE);
            let (sender, receiver, _, _) =
                psty_up_to_opprf(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            let (intersection_sender, _, payloads_len) =
                psty_check_opprf_payload(sender, receiver, payloads);
            assert!(
                intersection_sender == payloads_len,
                "PSTY: Error in sender's payloads hashing table : Expected to find {} payloads, found {}",
                payloads_len,
                intersection_sender
            );
        }
    }
    #[test]
    fn test_psty_opprf_sender_payloads_preserved_arbitrary_seed() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let set = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (sender, receiver, _, _) =
                psty_up_to_opprf(&set, &payloads, rng.random(), DEFAULT_SEED);
            let (intersection_sender, _, payloads_len) =
                psty_check_opprf_payload(sender, receiver, payloads);
            assert!(
                intersection_sender == payloads_len,
                "PSTY: Error in sender's payloads hashing table : Expected to find {} payloads, found {}",
                payloads_len,
                intersection_sender
            );
        }
    }
    #[test]
    fn test_psty_opprf_receiver_payloads_preserved_arbitrary_set() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let set = rand_u8_vec_unique(SET_SIZE, ELEMENT_MAX, &mut rng);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (sender, receiver, _, _) =
                psty_up_to_opprf(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            let (_, intersection_receiver, payloads_len) =
                psty_check_opprf_payload(sender, receiver, payloads);
            assert!(
                intersection_receiver == payloads_len,
                "PSTY: Error in receiver's payloads hashing table : Expected to find {} payloads, found {}",
                payloads_len,
                intersection_receiver
            );
        }
    }
    #[test]
    fn test_psty_opprf_receiver_payloads_preserved_arbitrary_payloads() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let set = rand_u8_vec_unique(SET_SIZE, ELEMENT_MAX, &mut rng);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (sender, receiver, _, _) =
                psty_up_to_opprf(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            let (_, intersection_receiver, payloads_len) =
                psty_check_opprf_payload(sender, receiver, payloads);
            assert!(
                intersection_receiver == payloads_len,
                "PSTY: Error in receiver's payloads hashing table : Expected to find {} payloads, found {}",
                payloads_len,
                intersection_receiver
            );
        }
    }
    #[test]
    fn test_psty_opprf_receiver_payloads_preserved_arbitrary_seed() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let set = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (sender, receiver, _, _) =
                psty_up_to_opprf(&set, &payloads, DEFAULT_SEED, rng.random());
            let (_, intersection_receiver, payloads_len) =
                psty_check_opprf_payload(sender, receiver, payloads);
            assert!(
                intersection_receiver == payloads_len,
                "PSTY: Error in receiver's payloads hashing table : Expected to find {} payloads, found {}",
                payloads_len,
                intersection_receiver
            );
        }
    }
}
