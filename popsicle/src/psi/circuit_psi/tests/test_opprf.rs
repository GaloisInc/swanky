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
    use std::os::unix::net::UnixStream;
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
    proptest! {
        #[test]
        fn test_psty_opprf_sender_succeeded(
            seed_sx in any::<u64>(),
            seed_rx in any::<u64>(),
            set in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX),
            payloads in arbitrary_payloads_block125(SET_SIZE, PAYLOAD_MAX)
        ){

            let (_, _, result_opprf_sender, _) = psty_up_to_opprf(&set, &payloads, seed_sx, seed_rx);
            assert!(
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
            assert!(
                !result_opprf_receiver.is_err(),
                "PSTY OPPRF failed on the receiver side"
            );
        }
    }
}
