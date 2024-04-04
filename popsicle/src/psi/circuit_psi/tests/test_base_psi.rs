//! Testing the Base Psi protocol
#[cfg(test)]
mod tests {
    use crate::errors::Error;
    use crate::psi::circuit_psi::{
        base_psi::{receiver::OpprfReceiver, sender::OpprfSender, BasePsi},
        tests::{utils::*, *},
        *,
    };
    use fancy_garbling::{
        twopac::semihonest::{Evaluator, Garbler},
        AllWire,
    };

    use ocelot::{ot::AlszReceiver as OtReceiver, ot::AlszSender as OtSender};
    use proptest::prelude::*;
    use scuttlebutt::{AesRng, Block512, Channel};

    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
        thread,
    };

    // Run Base Psi
    fn psty_base_psi(
        set: &[Vec<u8>],
        payloads: &[Block512],
        seed_sx: u64,
        seed_rx: u64,
    ) -> (
        Result<CircuitInputs<AllWire>, Error>,
        Result<CircuitInputs<AllWire>, Error>,
    ) {
        let (sender, receiver) = UnixStream::pair().unwrap();

        thread::scope(|s| {
            let result_sender = s.spawn(|| {
                let mut rng = AesRng::seed_from_u64(seed_sx);
                let mut channel = setup_channel(sender);
                let mut gb = Garbler::<
                    Channel<BufReader<UnixStream>, BufWriter<UnixStream>>,
                    AesRng,
                    OtSender,
                    AllWire,
                >::new(channel.clone(), rng.clone())
                .unwrap();
                OpprfSender::base_psi(&mut gb, &set, &payloads, &mut channel, &mut rng)
            });
            let mut rng = AesRng::seed_from_u64(seed_rx);
            let mut channel = setup_channel(receiver);
            let mut ev = Evaluator::<
                Channel<BufReader<UnixStream>, BufWriter<UnixStream>>,
                AesRng,
                OtReceiver,
                AllWire,
            >::new(channel.clone(), rng.clone())
            .unwrap();
            let result_receiver =
                OpprfReceiver::base_psi(&mut ev, &set, &payloads, &mut channel, &mut rng);
            (result_sender.join().unwrap(), result_receiver)
        })
    }
    proptest! {
         #[test]
         // Test that the Base Psi Sender produced no errors
        fn test_psty_base_psi_sender_succeeded_arbitrary_set(
            set in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX),
        ){
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (result_sender, _) = psty_base_psi(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            prop_assert!(
                !result_sender.is_err(),
                "PSTY's Base Psi failed on the sender side"
            );
        }
                 #[test]
         // Test that the Base Psi Sender produced no errors
        fn test_psty_base_psi_sender_succeeded_arbitrary_payloads(
            payloads in arbitrary_payloads_block125(SET_SIZE, PAYLOAD_MAX)
        ){
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let (result_sender, _) = psty_base_psi(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            prop_assert!(
                !result_sender.is_err(),
                "PSTY's Base Psi failed on the sender side"
            );
        }
                 #[test]
         // Test that the Base Psi Sender produced no errors
        fn test_psty_base_psi_sender_succeeded_arbitrary_seed(
            seed_sx in any::<u64>(),
        ){
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (result_sender, _) = psty_base_psi(&set, &payloads, seed_sx, DEFAULT_SEED);
            prop_assert!(
                !result_sender.is_err(),
                "PSTY's Base Psi failed on the sender side"
            );
        }
        #[test]
        // Test that the Base Psi Receiver produced no errors
        fn test_psty_base_psi_receiver_succeeded_arbitrary_sets(
            set in arbitrary_unique_sets(SET_SIZE, ELEMENT_MAX),
        ){
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (_, result_receiver) = psty_base_psi(&set, &payloads,  DEFAULT_SEED, DEFAULT_SEED);
            prop_assert!(
                !result_receiver.is_err(),
                "PSTY's Base Psi failed on the receiver side"
            );
        }
                #[test]
        // Test that the Base Psi Receiver produced no errors
        fn test_psty_base_psi_receiver_succeeded_arbitrary_payloads(
            payloads in arbitrary_payloads_block125(SET_SIZE, PAYLOAD_MAX)
        ){
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let (_, result_receiver) = psty_base_psi(&set, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            prop_assert!(
                !result_receiver.is_err(),
                "PSTY's Base Psi failed on the receiver side"
            );
        }
                #[test]
        // Test that the Base Psi Receiver produced no errors
        fn test_psty_base_psi_receiver_succeeded_arbitrary_seed(
            seed_rx in any::<u64>(),
        ){
            let set = enum_ids(SET_SIZE, 0, ELEMENT_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (_, result_receiver) = psty_base_psi(&set, &payloads, DEFAULT_SEED, seed_rx);
            prop_assert!(
                !result_receiver.is_err(),
                "PSTY's Base Psi failed on the receiver side"
            );
        }
    }
}
