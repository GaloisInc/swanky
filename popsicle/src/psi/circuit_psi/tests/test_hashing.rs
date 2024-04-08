//! Testing the hashing phase in Base Psi
#[cfg(test)]
mod tests {
    use crate::errors::Error;
    use crate::psi::circuit_psi::{
        base_psi::{receiver::OpprfReceiver, sender::OpprfSender, BasePsi},
        tests::{utils::*, *},
        *,
    };
    use scuttlebutt::{AesRng, Block512};
    use std::{collections::HashSet, os::unix::net::UnixStream, thread};

    // Run the base psi up to hashing
    fn psty_up_to_hashing(
        set: &[Vec<u8>],
        payloads: &[Block512],
        seed_sx: u64,
        seed_rx: u64,
    ) -> (
        OpprfSender,
        OpprfReceiver,
        Result<(), Error>,
        Result<(), Error>,
    ) {
        let (sender, receiver) = UnixStream::pair().unwrap();

        thread::scope(|s| {
            let result_sender = s.spawn(|| {
                let mut rng = AesRng::seed_from_u64(seed_sx);
                let mut channel = setup_channel(sender);
                let mut sender = OpprfSender::init(&mut channel, &mut rng, true).unwrap();
                let result_hash_sender = sender.hash_data(set, payloads, &mut channel, &mut rng);
                (sender, result_hash_sender)
            });
            let mut rng = AesRng::seed_from_u64(seed_rx);
            let mut channel = setup_channel(receiver);

            let mut receiver = OpprfReceiver::init(&mut channel, &mut rng, true).unwrap();
            let result_hash_receiver = receiver.hash_data(set, payloads, &mut channel, &mut rng);
            let (sender, result_hash_sender) = result_sender.join().unwrap();
            (sender, receiver, result_hash_sender, result_hash_receiver)
        })
    }

    // Check that hashing preserves the original payloads by intersecting the party's hash outputs
    // with the original payloads. The idea is that if the intersection cardinality in both cases is
    // equal to the original payload cardinality, then the hash outputs includes that set
    fn psty_check_hashing_payloads(
        sender: OpprfSender,
        receiver: OpprfReceiver,
        payloads: Vec<Block512>,
    ) -> (usize, usize, usize) {
        let payloads_hash: HashSet<Block512> = HashSet::from_iter(payloads);
        let receiver_payloads: HashSet<Block512> =
            HashSet::from_iter(receiver.state.opprf_payloads_in);

        let sender = sender.state;
        let sender_masked_payloads: Vec<Vec<Block512>> = sender.opprf_payloads_in;
        let sender_masks: Vec<Block512> = sender.opprf_payloads_out;

        // Payloads get masked by the sender to keep them hidden.
        // We need to unmask them to check that everything is fine.
        let mut sender_payloads: HashSet<Block512> = HashSet::new();
        for i in 0..sender_masks.len() {
            for j in 0..sender_masked_payloads[i].len() {
                sender_payloads.insert(sender_masked_payloads[i][j] ^ sender_masks[i]);
            }
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
    // Test that the OpprfSender produced no errors when
    // set is arbitrary
    fn test_psty_hashing_simple_sender_succeed_arbitrary_set() {
        for _ in 0..TEST_TRIALS {
            let mut rng = AesRng::new();
            let set = rand_u8_vec(SET_SIZE, ELEMENT_MAX, &mut rng);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (_, _, result_hash_sender, _) =
                psty_up_to_hashing(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            assert!(
                !result_hash_sender.is_err(),
                "PSTY Simple Hashing failed on the Sender side"
            );
        }
    }
    #[test]
    // Test that the OpprfSender produced no errors when
    // payloads are arbitrary
    fn test_psty_hashing_simple_sender_succeed_arbitrary_payload() {
        for _ in 0..TEST_TRIALS {
            let mut rng = AesRng::new();
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let payloads =
                int_vec_block512(rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng), PAYLOAD_SIZE);
            let (_, _, result_hash_sender, _) =
                psty_up_to_hashing(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            assert!(
                !result_hash_sender.is_err(),
                "PSTY Simple Hashing failed on the Sender side"
            );
        }
    }
    #[test]
    // Test that the OpprfSender produced no errors when
    // payloads are arbitrary
    fn test_psty_hashing_simple_sender_succeed_arbitrary_seed() {
        for _ in 0..TEST_TRIALS {
            let mut rng = AesRng::new();
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (_, _, result_hash_sender, _) =
                psty_up_to_hashing(&set, &payloads, rng.gen(), DEFAULT_SEED);
            assert!(
                !result_hash_sender.is_err(),
                "PSTY Simple Hashing failed on the Sender side"
            );
        }
    }
    #[test]
    // Test that the OpprfSender produced no errors when
    // payloads are arbitrary
    fn test_psty_hashing_simple_sender_succeeded_arbitrary_payload() {
        for _ in 0..TEST_TRIALS {
            let mut rng = AesRng::new();
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let payloads =
                int_vec_block512(rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng), PAYLOAD_SIZE);
            let (_, _, result_hash_sender, _) =
                psty_up_to_hashing(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            assert!(
                !result_hash_sender.is_err(),
                "PSTY Simple Hashing failed on the Sender side"
            );
        }
    }
    #[test]
    // Test that the OpprfSender produced no errors when
    // sx seed is arbitrary
    fn test_psty_hashing_simple_sender_succeeded_arbitrary_seed() {
        for _ in 0..TEST_TRIALS {
            let mut rng = AesRng::new();
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (_, _, result_hash_sender, _) =
                psty_up_to_hashing(&set, &payloads, rng.gen(), DEFAULT_SEED);
            assert!(
                !result_hash_sender.is_err(),
                "PSTY Simple Hashing failed on the Sender side"
            );
        }
    }
    #[test]
    // Test that the OpprfReceiver produced no errors
    // when set is arbitrary
    fn test_psty_hashing_cuckoo_receiver_succeeded_arbitrary_set() {
        for _ in 0..TEST_TRIALS {
            let mut rng = AesRng::new();
            let set = rand_u8_vec(SET_SIZE, ELEMENT_MAX, &mut rng);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (_, _, _, result_hash_receiver) =
                psty_up_to_hashing(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            assert!(
                !result_hash_receiver.is_err(),
                "PSTY Cuckoo Hashing failed on the Receiver side"
            );
        }
    }
    #[test]
    // Test that the OpprfReceiver produced no errors
    // when payloads are arbitrary
    fn test_psty_hashing_cuckoo_receiver_succeeded_arbitrary_payloads() {
        for _ in 0..TEST_TRIALS {
            let mut rng = AesRng::new();
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let payloads =
                int_vec_block512(rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng), PAYLOAD_SIZE);
            let (_, _, _, result_hash_receiver) =
                psty_up_to_hashing(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            assert!(
                !result_hash_receiver.is_err(),
                "PSTY Cuckoo Hashing failed on the Receiver side"
            );
        }
    }
    #[test]
    // Test that the OpprfReceiver produced no errors
    // when rx seed is arbitrary
    fn test_psty_hashing_cuckoo_receiver_succeeded_arbitrary_seed() {
        for _ in 0..TEST_TRIALS {
            let mut rng = AesRng::new();
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (_, _, _, result_hash_receiver) =
                psty_up_to_hashing(&set, &payloads, DEFAULT_SEED, rng.gen());
            assert!(
                !result_hash_receiver.is_err(),
                "PSTY Cuckoo Hashing failed on the Receiver side"
            );
        }
    }
    #[test]
    // Test that Simple Hashing preserved the original payloads
    fn test_psty_hashing_simple_sender_payloads_preserved_arbitrary_payloads() {
        for _ in 0..TEST_TRIALS {
            let mut rng = AesRng::new();
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let payloads =
                int_vec_block512(rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng), PAYLOAD_SIZE);
            let (sender, receiver, _, _) =
                psty_up_to_hashing(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            let (intersection_payloads_sx, _, payloads_len) =
                psty_check_hashing_payloads(sender, receiver, payloads);

            assert!(
                intersection_payloads_sx == payloads_len,
                "PSTY: Error in sender's payloads hashing table : Expected to find {} payloads, found {}",
                payloads_len,
                intersection_payloads_sx
            );
        }
    }
    #[test]
    // Test that Simple Hashing preserved the original payloads
    fn test_psty_hashing_simple_sender_payloads_preserved_arbitrary_seed() {
        for _ in 0..TEST_TRIALS {
            let mut rng = AesRng::new();
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (sender, receiver, _, _) =
                psty_up_to_hashing(&set, &payloads, rng.gen(), DEFAULT_SEED);
            let (intersection_payloads_sx, _, payloads_len) =
                psty_check_hashing_payloads(sender, receiver, payloads);

            assert!(
                intersection_payloads_sx == payloads_len,
                "PSTY: Error in sender's payloads hashing table : Expected to find {} payloads, found {}",
                payloads_len,
                intersection_payloads_sx
            );
        }
    }
    #[test]
    // Test that Cuckoo Hashing preserved the original payloads
    fn test_psty_hashing_cuckoo_receiver_payloads_preserved_arbitrary_payloads() {
        for _ in 0..TEST_TRIALS {
            let mut rng = AesRng::new();
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let payloads =
                int_vec_block512(rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng), PAYLOAD_SIZE);

            let (sender, receiver, _, _) =
                psty_up_to_hashing(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            let (_, intersection_payloads_rx, payloads_len) =
                psty_check_hashing_payloads(sender, receiver, payloads);
            assert!(
                intersection_payloads_rx == payloads_len,
                "PSTY: Error in receiver's payloads hashing table : Expected to find {} payloads, found {}",
                payloads_len,
                intersection_payloads_rx
            );
        }
    }
    #[test]
    // Test that Simple Hashing preserved the original payloads
    fn test_psty_hashing_cuckoo_receiver_payloads_preserved_arbitrary_seed() {
        for _ in 0..TEST_TRIALS {
            let mut rng = AesRng::new();
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (sender, receiver, _, _) =
                psty_up_to_hashing(&set, &payloads, DEFAULT_SEED, rng.gen());
            let (_, intersection_payloads_rx, payloads_len) =
                psty_check_hashing_payloads(sender, receiver, payloads);
            assert!(
                intersection_payloads_rx == payloads_len,
                "PSTY: Error in receiver's payloads hashing table : Expected to find {} payloads, found {}",
                payloads_len,
                intersection_payloads_rx
            );
        }
    }
    #[test]
    // Test that the Sender's payload and set hash tables have the same size
    fn test_psty_hashing_sizes_simple_sender_payload_set_same() {
        for _ in 0..TEST_TRIALS {
            let mut rng = AesRng::new();
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (sender, _, _, _) = psty_up_to_hashing(&set, &payloads, rng.gen(), DEFAULT_SEED);
            assert!(
                sender.state.opprf_payloads_in.len() == sender.state.opprf_set_in.len(),
                "PSTY Simple Hashing: the payloads and sets hash tables have different sizes, payloads: {}, set: {}",
                sender.state.opprf_payloads_in.len(), sender.state.opprf_set_in.len(),
            );
        }
    }
    #[test]
    // Test that the Sender's payload and set hash tables have the same size
    fn test_psty_hashing_sizes_simple_sender_payload_in_out_same() {
        for _ in 0..TEST_TRIALS {
            let mut rng = AesRng::new();
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (sender, _, _, _) = psty_up_to_hashing(&set, &payloads, rng.gen(), DEFAULT_SEED);
            assert!(
                sender.state.opprf_payloads_in.len() == sender.state.opprf_payloads_out.len(),
                "PSTY Simple Hashing: the payloads and payload mask tables have different sizes, payloads {}, masks {} ",
sender.state.opprf_payloads_in.len(), sender.state.opprf_payloads_out.len(),
            );
        }
    }
    #[test]
    // Test that the Sender's payload and set hash tables have the same size
    fn test_psty_hashing_sizes_simple_sender_set_in_out_same() {
        for _ in 0..TEST_TRIALS {
            let mut rng = AesRng::new();
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (sender, _, _, _) = psty_up_to_hashing(&set, &payloads, rng.gen(), DEFAULT_SEED);
            assert!(
                sender.state.opprf_set_in.len() == sender.state.opprf_set_out.len(),
                "PSTY Simple Hashing: the set and set programs tables have different sizes, set in {} set out {}",
                sender.state.opprf_set_in.len(), sender.state.opprf_set_out.len(),
            );
        }
    }
    #[test]
    // Test that the Sender's payload and set hash tables have the same size
    fn test_psty_hashing_sizes_receiver_cuckoo_payload_in_out_same() {
        for _ in 0..TEST_TRIALS {
            let mut rng = AesRng::new();
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (_, receiver, _, _) = psty_up_to_hashing(&set, &payloads, rng.gen(), DEFAULT_SEED);
            assert!(
                receiver.state.opprf_payloads_in.len() == receiver.state.opprf_set_in.len(),
                "PSTY Cuckoo Hashing: the payloads and sets hash tables have different sizes, payloads: {}, set {}",
                receiver.state.opprf_payloads_in.len(),
                receiver.state.opprf_set_in.len(),
            );
        }
    }
    #[test]
    // Test that the Sender's payload and set hash tables have the same size
    fn test_psty_hashing_sizes_sender_receiver_set_tables_same() {
        for _ in 0..TEST_TRIALS {
            let mut rng = AesRng::new();
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (sender, receiver, _, _) =
                psty_up_to_hashing(&set, &payloads, rng.gen(), DEFAULT_SEED);
            assert!(
                sender.state.opprf_set_in.len() == receiver.state.opprf_set_in.len(),
                "PSTY Hashing: the sender and receicver have differently sized set hashing tables, sender: {}, receiver: {}",
                sender.state.opprf_set_in.len(),
                receiver.state.opprf_set_in.len(),

            );
        }
    }
}
