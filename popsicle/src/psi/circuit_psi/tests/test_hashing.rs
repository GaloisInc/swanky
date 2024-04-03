//! Testing the hashing phase in Base Psi
//! Testing the hashing phase in Base Psi
#[cfg(test)]
mod tests {
    use crate::errors::Error;
    use crate::psi::circuit_psi::{
        base_psi::{receiver::OpprfReceiver, sender::OpprfSender, BasePsi},
        tests::utils::*,
        *,
    };

    use std::{collections::HashSet, thread};

    use proptest::prelude::*;
    use scuttlebutt::{AesRng, Block512};
    use std::os::unix::net::UnixStream;
    const SET_SIZE: usize = 1 << 8;

    const ELEMENT_MAX: u128 = u64::MAX as u128;
    const PAYLOAD_MAX: u128 = 100000;

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
                let mut channel = setup(sender);
                let mut sender = OpprfSender::init(&mut channel, &mut rng, true).unwrap();
                let result_hash_sender =
                    sender.hash_data(set, Some(payloads), &mut channel, &mut rng);
                (sender, result_hash_sender)
            });
            let mut rng = AesRng::seed_from_u64(seed_rx);
            let mut channel = setup(receiver);

            let mut receiver = OpprfReceiver::init(&mut channel, &mut rng, true).unwrap();
            let result_hash_receiver =
                receiver.hash_data(set, Some(payloads), &mut channel, &mut rng);
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
        let receiver_payloads: HashSet<Block512> = HashSet::from_iter(
            receiver
                .state
                .unwrap()
                .opprf_payloads_in
                .into_iter()
                .flatten(),
        );

        let sender = sender.state.unwrap();
        let sender_masked_payloads: Vec<Vec<Block512>> = sender.opprf_payloads_in.unwrap();
        let sender_masks: Vec<Block512> = sender.opprf_payloads_out.unwrap();

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
    // Check that hashing preserves the original set by intersecting the party's hash outputs
    // with the original set. The idea is that if the intersection cardinality in both cases is
    // equal to the original set cardinality, then the hash outputs includes that set
    fn psty_check_hashing_set(
        sender: OpprfSender,
        receiver: OpprfReceiver,
        set: &[Vec<u8>],
    ) -> (usize, usize) {
        let set_hash: HashSet<Block> = HashSet::from_iter(u8_vec_block(set, ELEMENT_SIZE));
        let sender_table: Vec<Block> = sender
            .state
            .unwrap()
            .opprf_set_in
            .into_iter()
            .flatten()
            .collect();
        let sender_table: HashSet<Block> = HashSet::from_iter(sender_table);
        let receiver_table: HashSet<Block> =
            HashSet::from_iter(receiver.state.unwrap().opprf_set_in);

        let intersection_size_sx = set_hash.intersection(&sender_table).count();
        let intersection_size_rx = set_hash.intersection(&receiver_table).count();
        (intersection_size_sx, intersection_size_rx)
    }

    proptest! {
         #[test]
         // Test that the OpprfSender produced no errors
        fn test_psty_simple_hashing_sender_succeeded(
            seed_sx in any::<u64>(),
            seed_rx in any::<u64>(),
            set in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX),
            payloads in arbitrary_payloads_block125(SET_SIZE, PAYLOAD_MAX)
        ){
            let (_, _, result_hash_sender, _) = psty_up_to_hashing(&set, &payloads, seed_sx, seed_rx);
            prop_assert!(
                !result_hash_sender.is_err(),
                "PSTY Simple Hashing failed on the Sender side"
            );
        }
        #[test]
        // Test that the OpprfReceiver produced no errors
        fn test_psty_cuckoo_hashing_receiver_succeeded(
            seed_sx in any::<u64>(),
            seed_rx in any::<u64>(),
            set in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX),
            payloads in arbitrary_payloads_block125(SET_SIZE, PAYLOAD_MAX)
        ){
            let (_, _, _, result_hash_receiver) = psty_up_to_hashing(&set, &payloads, seed_sx, seed_rx);
            prop_assert!(
                !result_hash_receiver.is_err(),
                "PSTY Cuckoo Hashing failed on the Receiver side"
            );
        }
        #[test]
        // Test that Simple Hashing preserved the sets
        fn test_psty_simple_hashing_sender_set_preserved(
            seed_sx in any::<u64>(),
            seed_rx in any::<u64>(),
            set in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX),
            payloads in arbitrary_payloads_block125(SET_SIZE, PAYLOAD_MAX)
        ){

            let (sender, receiver, _, _) = psty_up_to_hashing(&set, &payloads, seed_sx, seed_rx);
            let (intersection_size_sx, _) = psty_check_hashing_set(sender, receiver, &set);
            prop_assert!(
            intersection_size_sx
                    == SET_SIZE,
                "PSTY simple hashing did not preserve input set on the sender side, the intersection of the tables is {} and should be {}", intersection_size_sx, SET_SIZE
            );
        }
        #[test]
        // Test that Cuckoo Hashing preserved the sets
        fn test_psty_cuckoo_hashing_receiver_set_preserved(
            seed_sx in any::<u64>(),
            seed_rx in any::<u64>(),
            set in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX),
            payloads in arbitrary_payloads_block125(SET_SIZE, PAYLOAD_MAX)
        ){

            let (sender, receiver, _, _) = psty_up_to_hashing(&set, &payloads, seed_sx, seed_rx);
            let (_, intersection_size_rx) = psty_check_hashing_set(sender, receiver, &set);
            prop_assert!(
            intersection_size_rx
                    == SET_SIZE,
                "PSTY cuckoo hashing did not preserve input set on the receiver side, the intersection of the tables is {} and should be {}", intersection_size_rx, SET_SIZE
            );
        }
        #[test]
        // Test that Simple Hashing preserved the original payloads
        fn test_psty_simple_hashing_sender_payloads_preserved(
            seed_sx in any::<u64>(),
            seed_rx in any::<u64>(),
            set in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX),
            payloads in arbitrary_payloads_block125(SET_SIZE, PAYLOAD_MAX)
        ){

            let (sender, receiver, _, _) = psty_up_to_hashing(&set, &payloads, seed_sx, seed_rx);
            let (intersection_payloads_sx, _, payloads_len) =
                psty_check_hashing_payloads(sender, receiver, payloads);
            prop_assert!(
                intersection_payloads_sx == payloads_len,
                "PSTY: Error in sender's payloads hashing table : Expected to find {} payloads, found {}",
                payloads_len,
                intersection_payloads_sx
            );
        }
        #[test]
        // Test that Cuckoo Hashing preserved the original payloads
        fn test_psty_cuckoo_hashing_receiver_payloads_preserved(
            seed_sx in any::<u64>(),
            seed_rx in any::<u64>(),
            set in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX),
            payloads in arbitrary_payloads_block125(SET_SIZE, PAYLOAD_MAX)
        ){

            let (sender, receiver, _, _) = psty_up_to_hashing(&set, &payloads, seed_sx, seed_rx);
            let (_, intersection_payloads_rx, payloads_len) =
                psty_check_hashing_payloads(sender, receiver, payloads);
            prop_assert!(
                intersection_payloads_rx == payloads_len,
                "PSTY: Error in receiver's payloads hashing table : Expected to find {} payloads, found {}",
                payloads_len,
                intersection_payloads_rx
            );
        }
    }
}
