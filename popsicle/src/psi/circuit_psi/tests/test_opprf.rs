//! Testing the opprf phase in Base Psi
#[cfg(test)]
mod tests {
    use crate::errors::Error;
    use crate::psi::circuit_psi::{
        base_psi::{receiver::OpprfReceiver, sender::OpprfSender, BasePsi},
        tests::utils::*,
        *,
    };

    use std::thread;

    use proptest::prelude::*;
    use scuttlebutt::{AesRng, Block512};
    use std::{collections::HashSet, os::unix::net::UnixStream};
    const SET_SIZE: usize = 1 << 8;

    const ELEMENT_MAX: u128 = u64::MAX as u128;
    const PAYLOAD_MAX: u128 = 100000;

    // Run the base psi up to the opprf exchange
    fn psty_up_to_opprf(
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
                let _ = sender.hash_data(set, Some(payloads), &mut channel, &mut rng);
                let result_opprf_sender = sender.opprf_exchange(&mut channel, &mut rng);

                (sender, result_opprf_sender)
            });
            let mut rng = AesRng::seed_from_u64(seed_rx);
            let mut channel = setup(receiver);
            let mut receiver = OpprfReceiver::init(&mut channel, &mut rng, true).unwrap();
            let _ = receiver.hash_data(set, Some(payloads), &mut channel, &mut rng);
            let result_opprf_receiver = receiver.opprf_exchange(&mut channel, &mut rng);

            let (sender, result_opprf_sender) = result_sender.join().unwrap();
            (sender, receiver, result_opprf_sender, result_opprf_receiver)
        })
    }
    // Check that the opprf preserves the original set by intersecting the party's opprf outputs
    // with the original set. The idea is that if the intersection cardinality in both cases is
    // equal to the original set cardinality, then the hash outputs includes that set
    fn psty_check_opprf_set(
        sender: OpprfSender,
        receiver: OpprfReceiver,
        set: &[Vec<u8>],
    ) -> (usize, usize) {
        let set_hash: HashSet<Block512> = HashSet::from_iter(u8_vec_block512(set, ELEMENT_SIZE));
        let sender_table: HashSet<Block512> =
            HashSet::from_iter(sender.state.unwrap().opprf_set_out);
        let receiver_table: HashSet<Block512> =
            HashSet::from_iter(receiver.state.unwrap().opprf_set_out.unwrap());

        let intersection_size_sx = set_hash.intersection(&sender_table).count();
        let intersection_size_rx = set_hash.intersection(&receiver_table).count();
        (intersection_size_sx, intersection_size_rx)
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

        let receiver = receiver.state.unwrap();
        let receiver_payloads: HashSet<Block512> =
            HashSet::from_iter(receiver.opprf_payloads_in.into_iter().flatten());
        let receiver_masks: Vec<Block512> = receiver.opprf_payloads_out.unwrap();
        let sender_masked_payloads: Vec<Block512> =
            sender.state.unwrap().opprf_payloads_out.unwrap();

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
    proptest! {
        #[test]
        fn test_psty_opprf_sender_succeeded(
            seed_sx in any::<u64>(),
            seed_rx in any::<u64>(),
            set in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX),
            payloads in arbitrary_payloads_block125(SET_SIZE, PAYLOAD_MAX)
        ){

            let (_, _, result_opprf_sender, _) = psty_up_to_opprf(&set, &payloads, seed_sx, seed_rx);
            prop_assert!(
                !result_opprf_sender.is_err(),
                "PSTY OPPRF failed on the sender side"
            );
        }
        #[test]
        fn test_psty_opprf_receiver_succeeded(
            seed_sx in any::<u64>(),
            seed_rx in any::<u64>(),
            set in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX),
            payloads in arbitrary_payloads_block125(SET_SIZE, PAYLOAD_MAX)
        ){

            let (_, _, _, result_opprf_receiver) = psty_up_to_opprf(&set, &payloads, seed_sx, seed_rx);
            prop_assert!(
                !result_opprf_receiver.is_err(),
                "PSTY OPPRF failed on the receiver side"
            );
        }
        #[test]
        fn test_psty_opprf_sender_set_preserved(
            seed_sx in any::<u64>(),
            seed_rx in any::<u64>(),
            set in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX),
            payloads in arbitrary_payloads_block125(SET_SIZE, PAYLOAD_MAX)
        ){

            let (sender, receiver, _, _) = psty_up_to_opprf(&set, &payloads, seed_sx, seed_rx);
            let (intersection_size_sx , _) = psty_check_opprf_set(sender, receiver, &set);

            prop_assert!(
            intersection_size_sx
                    == SET_SIZE,
                "PSTY OpprfSender did not preserve the original set, the intersection of the tables is {} and should be {}", intersection_size_sx, SET_SIZE
            );
        }
        #[test]
        fn test_psty_opprf_receiver_set_preserved(
            seed_sx in any::<u64>(),
            seed_rx in any::<u64>(),
            set in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX),
            payloads in arbitrary_payloads_block125(SET_SIZE, PAYLOAD_MAX)
        ){

            let (sender, receiver, _, _) = psty_up_to_opprf(&set, &payloads, seed_sx, seed_rx);
            let (_ , intersection_size_rx) = psty_check_opprf_set(sender, receiver, &set);

            prop_assert!(
            intersection_size_rx
                    == SET_SIZE,
                "PSTY OpprfReceiver did not preserve the original set, the intersection of the tables is {} and should be {}", intersection_size_rx, SET_SIZE
            );
        }
        #[test]
        fn test_psty_opprf_sender_payloads_preserved(
            seed_sx in any::<u64>(),
            seed_rx in any::<u64>(),
            set in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX),
            payloads in arbitrary_payloads_block125(SET_SIZE, PAYLOAD_MAX)
        ){

            let (sender, receiver, _, _) = psty_up_to_opprf(&set, &payloads, seed_sx, seed_rx);
            let (intersection_sender, _, payloads_len) = psty_check_opprf_payload(sender, receiver, payloads);
            prop_assert!(
                intersection_sender == payloads_len,
                "PSTY: Error in sender's payloads hashing table : Expected to find {} payloads, found {}",
                payloads_len,
                intersection_sender
            );
        }
        #[test]
        fn test_psty_opprf_receiver_payloads_preserved(
            seed_sx in any::<u64>(),
            seed_rx in any::<u64>(),
            set in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX),
            payloads in arbitrary_payloads_block125(SET_SIZE, PAYLOAD_MAX)
        ){

            let (sender, receiver, _, _) = psty_up_to_opprf(&set, &payloads, seed_sx, seed_rx);
            let (_, intersection_receiver, payloads_len) = psty_check_opprf_payload(sender, receiver, payloads);
            prop_assert!(
                intersection_receiver == payloads_len,
                "PSTY: Error in receiver's payloads hashing table : Expected to find {} payloads, found {}",
                payloads_len,
                intersection_receiver
            );
        }
    }
}
