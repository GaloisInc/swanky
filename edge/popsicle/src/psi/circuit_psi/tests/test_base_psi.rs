//! Testing the Base Psi protocol
#[cfg(test)]
mod tests {
    use rand::RngExt;

    use crate::psi::circuit_psi::{
        base_psi::{BasePsi, receiver::OpprfReceiver, sender::OpprfSender},
        tests::{utils::*, *},
        utils::*,
        *,
    };
    use fancy_garbling::WireMod2;
    use swanky_twopac::semihonest::{Evaluator, Garbler};

    use swanky_block::Block512;
    use swanky_ot_alsz_kos::alsz::{Receiver as OtReceiver, Sender as OtSender};
    use swanky_rng::SwankyRng;

    // Run Base Psi
    fn psty_base_psi(
        primary_keys: &[Vec<u8>],
        payloads: &[Block512],
        seed_sx: u64,
        seed_rx: u64,
    ) -> (
        swanky_error::Result<CircuitInputs<WireMod2>>,
        swanky_error::Result<CircuitInputs<WireMod2>>,
    ) {
        swanky_channel::local::local_channel_pair(
            |channel| {
                let mut rng = SwankyRng::seed_from_u64(seed_sx);
                let mut gb = Garbler::<SwankyRng, OtSender, WireMod2>::new(
                    channel,
                    SwankyRng::from_rng(&mut rng),
                )
                .unwrap();
                Ok(OpprfSender::base_psi(
                    &mut gb,
                    primary_keys,
                    Some(payloads),
                    channel,
                    &mut rng,
                ))
            },
            |channel| {
                let mut rng = SwankyRng::seed_from_u64(seed_rx);
                let mut ev = Evaluator::<SwankyRng, OtReceiver, WireMod2>::new(
                    channel,
                    SwankyRng::from_rng(&mut rng),
                )
                .unwrap();
                Ok(OpprfReceiver::base_psi(
                    &mut ev,
                    primary_keys,
                    Some(payloads),
                    channel,
                    &mut rng,
                ))
            },
        )
        .unwrap()
    }

    #[test]
    // Test that the Base Psi Sender produced no errors
    fn test_psty_base_psi_sender_succeeded_arbitrary_primary_keys() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let primary_keys = rand_u8_vec_unique(SET_SIZE, ELEMENT_MAX, &mut rng);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (result_sender, _) =
                psty_base_psi(&primary_keys, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            assert!(
                result_sender.is_ok(),
                "PSTY's Base Psi failed on the sender side"
            );
        }
    }
    #[test]
    // Test that the Base Psi Sender produced no errors
    fn test_psty_base_psi_sender_succeeded_arbitrary_payloads() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let primary_keys = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
            let payloads =
                int_vec_block512(rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng), PAYLOAD_SIZE);
            let (result_sender, _) =
                psty_base_psi(&primary_keys, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            assert!(
                result_sender.is_ok(),
                "PSTY's Base Psi failed on the sender side"
            );
        }
    }
    #[test]
    // Test that the Base Psi Sender produced no errors
    fn test_psty_base_psi_sender_succeeded_arbitrary_seed() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let primary_keys = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (result_sender, _) =
                psty_base_psi(&primary_keys, &payloads, rng.random(), DEFAULT_SEED);
            assert!(
                result_sender.is_ok(),
                "PSTY's Base Psi failed on the sender side"
            );
        }
    }
    #[test]
    // Test that the Base Psi Receiver produced no errors
    fn test_psty_base_psi_receiver_succeeded_arbitrary_primary_keyss() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let primary_keys = rand_u8_vec_unique(SET_SIZE, ELEMENT_MAX, &mut rng);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (_, result_receiver) =
                psty_base_psi(&primary_keys, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            assert!(
                result_receiver.is_ok(),
                "PSTY's Base Psi failed on the receiver side"
            );
        }
    }
    #[test]
    // Test that the Base Psi Receiver produced no errors
    fn test_psty_base_psi_receiver_succeeded_arbitrary_payloads() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let primary_keys = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
            let payloads =
                int_vec_block512(rand_u128_vec(SET_SIZE, PAYLOAD_MAX, &mut rng), PAYLOAD_SIZE);
            let (_, result_receiver) =
                psty_base_psi(&primary_keys, &payloads, DEFAULT_SEED, DEFAULT_SEED);
            assert!(
                result_receiver.is_ok(),
                "PSTY's Base Psi failed on the receiver side"
            );
        }
    }
    #[test]
    // Test that the Base Psi Receiver produced no errors
    fn test_psty_base_psi_receiver_succeeded_arbitrary_seed() {
        for _ in 0..TEST_TRIALS {
            let mut rng = SwankyRng::new();
            let primary_keys = enum_ids(SET_SIZE, 0, PRIMARY_KEY_SIZE);
            let payloads = int_vec_block512(vec![1u128; SET_SIZE], PAYLOAD_SIZE);
            let (_, result_receiver) =
                psty_base_psi(&primary_keys, &payloads, DEFAULT_SEED, rng.random());
            assert!(
                result_receiver.is_ok(),
                "PSTY's Base Psi failed on the receiver side"
            );
        }
    }
}
