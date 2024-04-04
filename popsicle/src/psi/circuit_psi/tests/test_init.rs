//! Testing the initialization phase in Base Psi
#[cfg(test)]
mod tests {

    use crate::{
        circuit_psi::tests::utils::setup,
        psi::circuit_psi::base_psi::{receiver::OpprfReceiver, sender::OpprfSender, BasePsi},
    };
    use rand::SeedableRng;
    use scuttlebutt::AesRng;

    use proptest::prelude::*;
    use std::os::unix::net::UnixStream;
    proptest! {
            #[test]
            fn test_psty_init_receiver_succeeded(seed_sx in any::<u64>(), seed_rx in any::<u64>()){
                let (sender, receiver) = UnixStream::pair().unwrap();

                std::thread::spawn(move || {
                    let mut rng = AesRng::seed_from_u64(seed_sx);
                    let mut channel = setup(sender);
                    let _ = OpprfSender::init(&mut channel, &mut rng);
                });
                let mut rng = AesRng::seed_from_u64(seed_rx);
                let mut channel = setup(receiver);
                let receiver = OpprfReceiver::init(&mut channel, &mut rng);

                prop_assert!(
                    !receiver.is_err(),
                    "PSTY Initialization failed on the receiver side"
                );

        }
        #[test]
         fn test_psty_init_sender_succeeded(seed_sx in any::<u64>(), seed_rx in any::<u64>()){
                let (sender, receiver) = UnixStream::pair().unwrap();

                let sender = std::thread::spawn(move || {
                    let mut rng = AesRng::seed_from_u64(seed_sx);
                    let mut channel = setup(sender);

                   OpprfSender::init(&mut channel, &mut rng)

                });
                let mut rng = AesRng::seed_from_u64(seed_rx);
                let mut channel = setup(receiver);
                let _ = OpprfReceiver::init(&mut channel, &mut rng);

                 prop_assert!(
                    !sender.join().unwrap().is_err(),
                    "PSTY Initialization failed on the sender side"
                );
        }
    }
}
