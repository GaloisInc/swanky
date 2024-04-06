//! Testing the initialization phase in Base Psi
#[cfg(test)]
mod tests {

    use crate::{
        circuit_psi::tests::{utils::setup_channel, *},
        psi::circuit_psi::base_psi::{receiver::OpprfReceiver, sender::OpprfSender, BasePsi},
    };
    use scuttlebutt::AesRng;
    use std::os::unix::net::UnixStream;

    #[test]
    fn test_psty_init_receiver_succeeded() {
        for _ in 0..TEST_TRIALS {
            let (sender, receiver) = UnixStream::pair().unwrap();

            std::thread::spawn(move || {
                let mut rng = AesRng::new();
                let mut channel = setup_channel(sender);
                let _ = OpprfSender::init(&mut channel, &mut rng);
            });
            let mut rng = AesRng::new();
            let mut channel = setup_channel(receiver);
            let receiver = OpprfReceiver::init(&mut channel, &mut rng);

            assert!(
                !receiver.is_err(),
                "PSTY Initialization failed on the receiver side"
            );
        }
    }
    #[test]
    fn test_psty_init_sender_succeeded() {
        for _ in 0..TEST_TRIALS {
            let (sender, receiver) = UnixStream::pair().unwrap();

            let sender = std::thread::spawn(move || {
                let mut rng = AesRng::new();
                let mut channel = setup_channel(sender);

                OpprfSender::init(&mut channel, &mut rng)
            });
            let mut rng = AesRng::new();
            let mut channel = setup_channel(receiver);
            let _ = OpprfReceiver::init(&mut channel, &mut rng);

            assert!(
                !sender.join().unwrap().is_err(),
                "PSTY Initialization failed on the sender side"
            );
        }
    }
}
