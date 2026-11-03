//! Testing the initialization phase in Base Psi
#[cfg(test)]
mod tests {

    use crate::psi::circuit_psi::{
        base_psi::{BasePsi, receiver::OpprfReceiver, sender::OpprfSender},
        tests::*,
    };
    use swanky_rng::SwankyRng;

    #[test]
    fn test_psty_init_receiver_succeeded() {
        for _ in 0..TEST_TRIALS {
            let (_, receiver) = swanky_channel::local::local_channel_pair(
                |channel| {
                    let mut rng = SwankyRng::new();
                    let _ = OpprfSender::init(true, channel, &mut rng);
                    Ok(())
                },
                |channel| {
                    let mut rng = SwankyRng::new();
                    let receiver = OpprfReceiver::init(true, channel, &mut rng);
                    Ok(receiver)
                },
            )
            .unwrap();

            assert!(
                receiver.is_ok(),
                "PSTY Initialization failed on the receiver side"
            );
        }
    }
    #[test]
    fn test_psty_init_sender_succeeded() {
        for _ in 0..TEST_TRIALS {
            let (sender, _) = swanky_channel::local::local_channel_pair(
                |channel| {
                    let mut rng = SwankyRng::new();
                    Ok(OpprfSender::init(true, channel, &mut rng))
                },
                |channel| {
                    let mut rng = SwankyRng::new();
                    let _ = OpprfReceiver::init(true, channel, &mut rng);
                    Ok(())
                },
            )
            .unwrap();

            assert!(
                sender.is_ok(),
                "PSTY Initialization failed on the sender side"
            );
        }
    }
}
